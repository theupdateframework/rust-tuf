//! An HTTP TUF repository server using the Tokio runtime (`#[tokio::main]`) and
//! `hyper` / `http-body-util` 1.x.
//!
//! It serves an ephemeral repository with TUF metadata and targets over HTTP,
//! drawing inspiration from `tuf/tests/simple_example.rs`, or optionally serves
//! from a local filesystem directory (`FileSystemRepository`).
//!
//! # Usage
//! ```bash
//! cargo run --example server-tokio -- [options]
//!
//! Options:
//!   --addr, -a <address:port>   Listen address and port (default: 127.0.0.1:8080)
//!   --dir, -d <directory>       Serve from a local directory (FileSystemRepository)
//!   --help, -h                  Print usage and exit
//! ```

use clap::Parser;
use futures_util::io::{AsyncReadExt as _, Cursor};
use http::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tuf::Result;
use tuf::crypto::Ed25519PrivateKey;
use tuf::metadata::{MetadataPath, MetadataVersion, TargetPath};
use tuf::pouf::{Pouf as _, Pouf1};
use tuf::repo_builder::RepoBuilder;
use tuf::repository::{EphemeralRepository, FileSystemRepository, RepositoryProvider};

#[derive(Parser, Debug)]
#[command(about = "An HTTP TUF repository server using the Tokio runtime and hyper 1.x")]
struct Cli {
    /// Listen address and port
    #[arg(
        short = 'a',
        long,
        env = "TUF_SERVER_ADDR",
        default_value = "127.0.0.1:8080"
    )]
    addr: SocketAddr,

    /// Serve from a local directory (FileSystemRepository)
    #[arg(short = 'd', long, env = "TUF_SERVER_DIR")]
    dir: Option<PathBuf>,
}

const ED25519_1_PK8: &[u8] = include_bytes!("../../tuf/tests/ed25519/ed25519-1.pk8.der");
const ED25519_2_PK8: &[u8] = include_bytes!("../../tuf/tests/ed25519/ed25519-2.pk8.der");
const ED25519_3_PK8: &[u8] = include_bytes!("../../tuf/tests/ed25519/ed25519-3.pk8.der");
const ED25519_4_PK8: &[u8] = include_bytes!("../../tuf/tests/ed25519/ed25519-4.pk8.der");

pub enum ServerRepo {
    Ephemeral(EphemeralRepository<Pouf1>),
    FileSystem(FileSystemRepository<Pouf1>),
}

impl ServerRepo {
    pub async fn fetch(&self, path: &str) -> Option<Vec<u8>> {
        match self {
            ServerRepo::Ephemeral(repo) => fetch_from_repo_provider(repo, path).await,
            ServerRepo::FileSystem(repo) => fetch_from_repo_provider(repo, path).await,
        }
    }
}

async fn run() -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = Cli::parse();
    let addr = cli.addr;
    let dir_path = cli.dir;

    let repo = match dir_path {
        Some(dir) => {
            println!("Serving TUF repository from local directory: {:?}", dir);
            Arc::new(ServerRepo::FileSystem(FileSystemRepository::<Pouf1>::new(
                dir,
            )))
        }
        None => {
            println!("Serving sample in-memory TUF repository (EphemeralRepository)");
            let mut remote = EphemeralRepository::<Pouf1>::new();
            init_server(&mut remote, true).await?;
            Arc::new(ServerRepo::Ephemeral(remote))
        }
    };

    let listener = TcpListener::bind(addr).await?;
    println!("TUF HTTP server listening on http://{}", addr);

    loop {
        let (tcp_stream, remote_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(err) => {
                eprintln!("Failed to accept connection: {}", err);
                continue;
            }
        };

        let io = TokioIo::new(tcp_stream);
        let repo = Arc::clone(&repo);

        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let repo = Arc::clone(&repo);
                async move { handle_request(req, repo).await }
            });

            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                eprintln!("Error serving connection from {}: {}", remote_addr, err);
            }
        });
    }
}

/// Initialize the server's repository with signed metadata and a sample target file.
async fn init_server(
    remote: &mut EphemeralRepository<Pouf1>,
    consistent_snapshot: bool,
) -> Result<()> {
    let root_key = Ed25519PrivateKey::from_pkcs8(ED25519_1_PK8)?;
    let snapshot_key = Ed25519PrivateKey::from_pkcs8(ED25519_2_PK8)?;
    let targets_key = Ed25519PrivateKey::from_pkcs8(ED25519_3_PK8)?;
    let timestamp_key = Ed25519PrivateKey::from_pkcs8(ED25519_4_PK8)?;

    let target_path = TargetPath::new("foo-bar")?;
    let target_file: &[u8] = b"things fade, alternatives exclude";

    RepoBuilder::create(&mut *remote)
        .trusted_root_keys(&[&root_key])
        .trusted_snapshot_keys(&[&snapshot_key])
        .trusted_targets_keys(&[&targets_key])
        .trusted_timestamp_keys(&[&timestamp_key])
        .stage_root_with_builder(|builder| builder.consistent_snapshot(consistent_snapshot))
        .unwrap()
        .add_target(target_path, Cursor::new(target_file))
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();

    Ok(())
}

/// Handle incoming HTTP requests and serve metadata or target files from the repository.
async fn handle_request(
    req: Request<Incoming>,
    repo: Arc<ServerRepo>,
) -> std::result::Result<Response<Full<Bytes>>, Infallible> {
    if req.method() != Method::GET {
        let mut resp = Response::new(Full::new(Bytes::from("Method Not Allowed")));
        *resp.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
        return Ok(resp);
    }

    let path = req.uri().path().trim_start_matches('/');
    if let Some(buf) = repo.fetch(path).await {
        let resp = Response::new(Full::new(Bytes::from(buf)));
        Ok(resp)
    } else {
        let mut resp = Response::new(Full::new(Bytes::from("Not Found")));
        *resp.status_mut() = StatusCode::NOT_FOUND;
        Ok(resp)
    }
}

/// Attempt to fetch either a metadata file or a target file from any `RepositoryProvider`.
/// Includes prefix-stripping fallback for paths requested with custom metadata/targets prefixes.
async fn fetch_from_repo_provider<R: RepositoryProvider<Pouf1>>(
    repo: &R,
    path: &str,
) -> Option<Vec<u8>> {
    let ext = format!(".{}", Pouf1::extension());
    if path.ends_with(&ext) {
        let (dir_prefix, filename) = match path.rsplit_once('/') {
            Some((dir, file)) => (dir, file),
            None => ("", path),
        };

        let stem = &filename[..filename.len() - ext.len()];
        let (version, role_str) = match stem.split_once('.') {
            Some((ver_str, r_str)) => match ver_str.parse::<NonZeroU32>() {
                Ok(num) => (Some(MetadataVersion::new(num)), r_str),
                Err(_) => (None, stem),
            },
            None => (None, stem),
        };

        let role_path_str = if dir_prefix.is_empty() {
            role_str.to_string()
        } else {
            format!("{}/{}", dir_prefix, role_str)
        };

        // Try exact role path first.
        if let Ok(meta_path) = MetadataPath::new(role_path_str)
            && let Ok(mut reader) = repo.fetch_metadata(&meta_path, version).await
        {
            let mut buf = Vec::new();
            if reader.read_to_end(&mut buf).await.is_ok() {
                return Some(buf);
            }
        }

        // Fallback: if dir_prefix was non-empty (e.g. client requested `metadata/1.root.json`),
        // try querying without the leading directory prefix.
        if !dir_prefix.is_empty()
            && let Ok(meta_path) = MetadataPath::new(role_str.to_string())
            && let Ok(mut reader) = repo.fetch_metadata(&meta_path, version).await
        {
            let mut buf = Vec::new();
            if reader.read_to_end(&mut buf).await.is_ok() {
                return Some(buf);
            }
        }
    }

    // Try exact target path.
    if let Ok(target_path) = TargetPath::new(path)
        && let Ok(mut reader) = repo.fetch_target(&target_path).await
    {
        let mut buf = Vec::new();
        if reader.read_to_end(&mut buf).await.is_ok() {
            return Some(buf);
        }
    }

    // Fallback: if target path had a leading directory prefix (e.g. `targets/foo-bar`),
    // try querying with just the filename.
    if let Some((_, filename)) = path.rsplit_once('/')
        && let Ok(target_path) = TargetPath::new(filename)
        && let Ok(mut reader) = repo.fetch_target(&target_path).await
    {
        let mut buf = Vec::new();
        if reader.read_to_end(&mut buf).await.is_ok() {
            return Some(buf);
        }
    }

    None
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    run().await
}
