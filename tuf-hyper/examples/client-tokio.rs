//! A TUF client using the Tokio runtime (`#[tokio::main]`) and hyper legacy client.
//!
//! Demonstrates constructing an `HttpRepositoryBuilder` with the pooling client
//! using `TokioExecutor`, setting up a local `EphemeralRepository` or `FileSystemRepository`,
//! initializing `Client::with_trusted_root_keys(...)`, running `.update().await`,
//! and downloading target files.
//!
//! # Usage
//! ```bash
//! # Make sure `server-tokio` is running first:
//! # cargo run --example server-tokio
//!
//! cargo run --example client-tokio -- [options]
//!
//! Options:
//!   --url, -u <url>        TUF server URL (default: http://127.0.0.1:8080)
//!   --dir, -d <directory>  Local metadata/target storage directory (FileSystemRepository)
//!   --help, -h             Print usage and exit
//! ```

use clap::Parser;
use futures_util::io::AsyncReadExt as _;
use http::{Request, Response, Uri};
use hyper::body::{Bytes, Incoming};
use hyper_util::client::pool::cache;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::future::Future;
use std::io;
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
#[command(about = "A TUF client using the Tokio runtime and hyper pooling client.")]
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

/// A custom hyper `Service<Uri>` connector for Tokio that establishes TCP connections
/// and performs HTTP/1 handshakes.
#[derive(Clone, Copy, Debug)]
pub struct TokioConnector;

impl Service<Uri> for TokioConnector {
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
            let stream = tokio::net::TcpStream::connect((host, port)).await?;
            let io = TokioIo::new(stream);
            let (sender, conn) = hyper::client::conn::http1::handshake(io).await?;
            tokio::spawn(async move {
                if let Err(err) = conn.await {
                    eprintln!("Connection failed: {:?}", err);
                }
            });
            Ok(ConnectionService(sender))
        })
    }
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = Cli::parse();
    let uri = cli.url;
    let local_dir = cli.dir;
    println!("Connecting to TUF HTTP repository at {} via Tokio", uri);

    // Build the pooling client using hyper_util::client::pool::cache and TokioExecutor
    let pool = cache::builder()
        .executor(TokioExecutor::new())
        .build(TokioConnector);
    let hyper_client =
        ServiceBuilder::new().service_fn(move |req: Request<http_body_util::Empty<Bytes>>| {
            let mut pool = pool.clone();
            async move {
                let mut conn = pool.call(req.uri().clone()).await?;
                conn.ready().await?.call(req).await
            }
        });

    // Construct the remote HTTP repository.
    let remote = HttpRepositoryBuilder::<_, Pouf1>::new(uri, hyper_client)
        .user_agent("tuf-client-tokio-example/0.1")
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
