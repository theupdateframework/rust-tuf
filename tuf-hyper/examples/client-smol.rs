//! A TUF client using the Smol runtime (`smol::block_on`) and hyper legacy client.
//!
//! Demonstrates implementing a custom `SmolExecutor` (`hyper::rt::Executor`),
//! `SmolStream` (`hyper::rt::Read` + `hyper::rt::Write` + `Connection`), and
//! `SmolConnector` (`Service<Uri>`), constructing an `HttpRepositoryBuilder` on Smol,
//! setting up a local `EphemeralRepository` or `FileSystemRepository`, initializing
//! the client with trusted root keys, running `.update().await`, and fetching target files.
//!
//! # Usage
//! ```bash
//! # Make sure `server-tokio` is running first:
//! # cargo run --example server-tokio
//!
//! cargo run --example client-smol -- [options]
//!
//! Options:
//!   --url, -u <url>        TUF server URL (default: http://127.0.0.1:8080)
//!   --dir, -d <directory>  Local metadata/target storage directory (FileSystemRepository)
//!   --help, -h             Print usage and exit
//! ```

use clap::Parser;
use futures_io::{AsyncRead, AsyncWrite};
use futures_util::io::AsyncReadExt as _;
use http::{Request, Response, Uri};
use hyper::body::{Bytes, Incoming};
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper_util::client::pool::cache;
use std::future::Future;
use std::io;
use std::mem::MaybeUninit;
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};
use tower::{Service, ServiceBuilder, ServiceExt as _};
use tuf::client::{Client, Config};
use tuf::crypto::{Ed25519PrivateKey, PrivateKey};
use tuf::metadata::{MetadataThreshold, MetadataVersion, TargetPath};
use tuf::pouf::Pouf1;
use tuf::repository::{
    EphemeralRepository, FileSystemRepository, RepositoryProvider, RepositoryStorage,
};
use tuf_hyper::HttpRepositoryBuilder;

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Parser, Debug)]
#[command(about = "A TUF client using the Smol runtime and hyper pooling client.")]
struct Cli {
    /// TUF server URL
    #[arg(
        short = 'u',
        long,
        env = "TUF_SERVER_URL",
        default_value = "http://127.0.0.1:8080"
    )]
    url: Uri,

    /// Local metadata/target storage directory (FileSystemRepository)
    #[arg(short = 'd', long, env = "TUF_LOCAL_DIR")]
    dir: Option<PathBuf>,
}

const ED25519_1_PK8: &[u8] = include_bytes!("../../tuf/tests/ed25519/ed25519-1.pk8.der");

/// A custom hyper runtime executor powered by `smol::spawn`.
#[derive(Clone, Copy, Debug)]
pub struct SmolExecutor;

impl<F> hyper::rt::Executor<F> for SmolExecutor
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, fut: F) {
        smol::spawn(async move {
            fut.await;
        })
        .detach();
    }
}

/// A wrapper around `smol::net::TcpStream` that implements hyper's `Read` and `Write`.
pub struct SmolStream {
    inner: smol::net::TcpStream,
}

impl Read for SmolStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut cursor: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        // SAFETY: Ensure that all bytes are initialized.
        //
        // FIXME(https://github.com/hyperium/hyper/pull/4115): We can replace the unsafe block with
        // this once it is in a release.
        // let slice = cursor.initialize_unfilled();
        let slice = unsafe {
            let uninit = cursor.as_mut();
            uninit.fill(MaybeUninit::new(0));

            std::slice::from_raw_parts_mut(uninit.as_mut_ptr() as *mut u8, uninit.len())
        };
        match Pin::new(&mut self.inner).poll_read(cx, slice) {
            Poll::Ready(Ok(n)) => {
                // SAFETY: We initialized all the bytes earlier in the function.
                unsafe { cursor.advance(n) };

                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Write for SmolStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

/// Wrapper around `hyper::client::conn::http1::SendRequest<B>` implementing `Service<Request<B>>`.
#[derive(Debug)]
pub struct ConnectionService<B>(pub hyper::client::conn::http1::SendRequest<B>);

impl<B> Service<Request<B>> for ConnectionService<B>
where
    B: hyper::body::Body + Send + 'static + Unpin,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    type Response = Response<Incoming>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.0.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let fut = self.0.send_request(req);
        Box::pin(async move { fut.await.map_err(Into::into) })
    }
}

/// A custom hyper `Service<Uri>` connector that establishes TCP connections via `smol::net::TcpStream`
/// and performs HTTP/1 handshakes.
#[derive(Clone, Copy, Debug)]
pub struct SmolConnector;

impl Service<Uri> for SmolConnector {
    type Response = ConnectionService<http_body_util::Empty<Bytes>>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        Box::pin(async move {
            let host = uri.host().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "Missing host in URI")
            })?;
            let port = uri.port_u16().unwrap_or(80);
            let addr_str = format!("{}:{}", host, port);
            let stream = smol::net::TcpStream::connect(addr_str).await?;
            let (sender, conn) =
                hyper::client::conn::http1::handshake(SmolStream { inner: stream }).await?;
            smol::spawn(async move {
                if let Err(err) = conn.await {
                    eprintln!("Connection failed: {:?}", err);
                }
            })
            .detach();
            Ok(ConnectionService(sender))
        })
    }
}

async fn async_main() -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = Cli::parse();
    let uri = cli.url;
    let local_dir = cli.dir;
    println!("Connecting to TUF HTTP repository at {} via Smol", uri);

    // Build the pooling client using hyper_util::client::pool::cache and SmolExecutor
    let pool = cache::builder().executor(SmolExecutor).build(SmolConnector);
    let hyper_client =
        ServiceBuilder::new().service_fn(move |req: Request<http_body_util::Empty<Bytes>>| {
            let mut pool = pool.clone();
            async move {
                let mut conn = pool.call(req.uri().clone()).await?;
                conn.ready().await?.call(req).await
            }
        });

    let remote = HttpRepositoryBuilder::<_, Pouf1>::new(uri, hyper_client)
        .user_agent("tuf-client-smol-example/0.1")
        .build();

    // Load the trusted root public key used by our example server.
    let root_key = Ed25519PrivateKey::from_pkcs8(ED25519_1_PK8)?;
    let root_public_key = root_key.public();

    let config = Config::default();

    match local_dir {
        Some(dir) => {
            println!("Using local FileSystemRepository at {:?}", dir);
            let local = FileSystemRepository::<Pouf1>::new(dir);
            run_client(config, root_public_key, local, remote).await?;
        }
        None => {
            println!("Using local EphemeralRepository (in-memory)");
            let local = EphemeralRepository::<Pouf1>::new();
            run_client(config, root_public_key, local, remote).await?;
        }
    }

    Ok(())
}

async fn run_client<L, R>(
    config: Config,
    root_public_key: &tuf::crypto::PublicKey,
    local: L,
    remote: R,
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    L: RepositoryProvider<Pouf1> + RepositoryStorage<Pouf1> + Send + Sync + 'static,
    R: RepositoryProvider<Pouf1> + Send + Sync + 'static,
{
    let mut client = Client::with_trusted_root_keys(
        config,
        MetadataVersion::ONE,
        MetadataThreshold::ONE,
        [root_public_key],
        local,
        remote,
    )
    .await?;

    println!("Updating client metadata...");
    let _ = client.update().await?;
    println!("Client metadata updated successfully.");

    // Fetch the target file into the local repository and verify its content.
    let target_path = TargetPath::new("foo-bar")?;
    println!("Fetching target '{}' to local storage...", target_path);
    client.fetch_target_to_local(&target_path).await?;

    let mut target_reader = client.fetch_target(&target_path).await?;
    let mut target_data = Vec::new();
    target_reader.read_to_end(&mut target_data).await?;
    println!(
        "Successfully fetched target '{}': {:?}",
        target_path,
        String::from_utf8_lossy(&target_data)
    );

    Ok(())
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    smol::block_on(async_main())
}
