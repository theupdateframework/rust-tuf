//! Read-only Repository implementation backed by a web server.

use futures_io::AsyncRead;
use futures_util::future::{BoxFuture, FutureExt as _};
use futures_util::stream::TryStreamExt;
use http::{Request, Response, StatusCode, Uri};
use http_body_util::BodyExt;
use hyper::body::{Body, Bytes};
use percent_encoding::utf8_percent_encode;
use std::borrow::Cow;
use std::io;
use std::marker::PhantomData;
use tower::{Service, ServiceExt as _};

use crate::enforce_minimum_bitrate::EnforceMinimumBitrate;
use tuf::Result;
use tuf::error::Error;
use tuf::metadata::{MetadataPath, MetadataVersion, TargetPath};
use tuf::pouf::Pouf;
use tuf::repository::RepositoryProvider;

/// A builder to create a repository accessible over HTTP.
///
/// # Example
///
/// ```no_run
/// use http::Uri;
/// use hyper_util::client::legacy::Client;
/// use hyper_util::rt::TokioExecutor;
/// use tuf::pouf::Pouf1;
/// use tuf_hyper::HttpRepositoryBuilder;
///
/// let client = Client::builder(TokioExecutor::new()).build_http();
/// let repository = HttpRepositoryBuilder::<_, Pouf1>::new(
///     Uri::from_static("https://example.com/tuf"),
///     client,
/// )
/// .user_agent("tuf-client/1.0")
/// .build();
/// ```
pub struct HttpRepositoryBuilder<
    S,
    D,
    B = http_body_util::Empty<Bytes>,
    ResBody = hyper::body::Incoming,
> where
    S: Service<Request<B>, Response = Response<ResBody>>,
    D: Pouf,
{
    uri: Uri,
    client: S,
    user_agent: Option<String>,
    metadata_prefix: Option<Vec<String>>,
    targets_prefix: Option<Vec<String>>,
    min_bytes_per_second: u32,
    _pouf: PhantomData<(D, fn() -> (B, ResBody))>,
}

impl<S, D, ResBody> HttpRepositoryBuilder<S, D, http_body_util::Empty<Bytes>, ResBody>
where
    S: Service<Request<http_body_util::Empty<Bytes>>, Response = Response<ResBody>>,
    D: Pouf,
{
    /// Create a new repository with the given `Uri` and `Service` client.
    pub fn new(uri: Uri, client: S) -> Self {
        HttpRepositoryBuilder {
            uri,
            client,
            user_agent: None,
            metadata_prefix: None,
            targets_prefix: None,
            min_bytes_per_second: 4096,
            _pouf: PhantomData,
        }
    }

    /// Create a new repository with the given `Uri` and `Service` client.
    pub fn new_with_uri(uri: Uri, client: S) -> Self {
        Self::new(uri, client)
    }
}

impl<S, D, B, ResBody> HttpRepositoryBuilder<S, D, B, ResBody>
where
    S: Service<Request<B>, Response = Response<ResBody>>,
    D: Pouf,
{
    /// Create a new repository with the given `Uri` and a `Service` client with a custom request body type `B`.
    pub fn new_with_body(uri: Uri, client: S) -> Self {
        HttpRepositoryBuilder {
            uri,
            client,
            user_agent: None,
            metadata_prefix: None,
            targets_prefix: None,
            min_bytes_per_second: 4096,
            _pouf: PhantomData,
        }
    }

    /// Create a new repository with the given `Uri` and a `Service` client with a custom request body type `B`.
    pub fn new_with_uri_and_body(uri: Uri, client: S) -> Self {
        Self::new_with_body(uri, client)
    }

    /// Set the User-Agent prefix.
    ///
    /// Callers *should* include a custom User-Agent prefix to help maintainers of TUF repositories
    /// keep track of which client versions exist in the field.
    ///
    pub fn user_agent<T: Into<String>>(mut self, user_agent: T) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// The argument `metadata_prefix` is used to provide an alternate path where metadata is
    /// stored on the repository. If `None`, this defaults to `/`. For example, if there is a TUF
    /// repository at `https://tuf.example.com/`, but all metadata is stored at `/meta/`, then
    /// passing the arg `Some("meta".into())` would cause `root.json` to be fetched from
    /// `https://tuf.example.com/meta/root.json`.
    pub fn metadata_prefix(mut self, metadata_prefix: Vec<String>) -> Self {
        self.metadata_prefix = Some(metadata_prefix);
        self
    }

    /// The argument `targets_prefix` is used to provide an alternate path where targets is
    /// stored on the repository. If `None`, this defaults to `/`. For example, if there is a TUF
    /// repository at `https://tuf.example.com/`, but all targets are stored at `/targets/`, then
    /// passing the arg `Some("targets".into())` would cause `hello-world` to be fetched from
    /// `https://tuf.example.com/targets/hello-world`.
    pub fn targets_prefix(mut self, targets_prefix: Vec<String>) -> Self {
        self.targets_prefix = Some(targets_prefix);
        self
    }

    /// Set the minimum bytes per second for a read to be considered good.
    pub fn min_bytes_per_second(mut self, min: u32) -> Self {
        self.min_bytes_per_second = min;
        self
    }

    /// Build a `HttpRepository`.
    pub fn build(self) -> HttpRepository<S, D, B, ResBody> {
        let user_agent = match self.user_agent {
            Some(user_agent) => user_agent,
            None => "rust-tuf".into(),
        };

        HttpRepository {
            uri: self.uri,
            client: self.client,
            user_agent,
            metadata_prefix: self.metadata_prefix,
            targets_prefix: self.targets_prefix,
            min_bytes_per_second: self.min_bytes_per_second,
            _pouf: PhantomData,
        }
    }
}

/// A repository accessible over HTTP.
#[derive(Debug)]
pub struct HttpRepository<S, D, B = http_body_util::Empty<Bytes>, ResBody = hyper::body::Incoming>
where
    S: Service<Request<B>, Response = Response<ResBody>>,
    D: Pouf,
{
    uri: Uri,
    client: S,
    user_agent: String,
    metadata_prefix: Option<Vec<String>>,
    targets_prefix: Option<Vec<String>>,
    min_bytes_per_second: u32,
    _pouf: PhantomData<(D, fn() -> (B, ResBody))>,
}

// Configuration for urlencoding URI path elements.
// From https://url.spec.whatwg.org/#path-percent-encode-set
const URLENCODE_FRAGMENT: &percent_encoding::AsciiSet = &percent_encoding::CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'<')
    .add(b'>')
    .add(b'`');
const URLENCODE_PATH: &percent_encoding::AsciiSet = &URLENCODE_FRAGMENT
    .add(b'#')
    .add(b'?')
    .add(b'{')
    .add(b'}')
    .add(b'%');

fn extend_uri(uri: &Uri, prefix: &Option<Vec<String>>, components: &[String]) -> Result<Uri> {
    let uri = uri.clone();
    let mut uri_parts = uri.into_parts();

    let (path, query) = match &uri_parts.path_and_query {
        Some(path_and_query) => (path_and_query.path(), path_and_query.query()),
        None => ("", None),
    };

    let modified_path = path.strip_suffix('/').unwrap_or(path);
    let mut path_split: Vec<Cow<'_, str>> = modified_path.split('/').map(Cow::Borrowed).collect();

    if let Some(prefix) = prefix {
        path_split.extend(prefix.iter().map(|s| Cow::Borrowed(s.as_str())));
    }
    path_split.extend(
        components
            .iter()
            .map(|s| utf8_percent_encode(s, URLENCODE_PATH).into()),
    );
    let constructed_path = path_split.join("/");

    uri_parts.path_and_query =
        match query {
            Some(query) => Some(format!("{}?{}", constructed_path, query).parse().map_err(
                |_| {
                    Error::IllegalArgument(format!(
                        "Invalid path and query: {:?}, {:?}",
                        constructed_path, query
                    ))
                },
            )?),
            None => Some(constructed_path.parse().map_err(|_| {
                Error::IllegalArgument(format!("Invalid URI path: {:?}", constructed_path))
            })?),
        };

    Uri::from_parts(uri_parts).map_err(|_| {
        Error::IllegalArgument(format!(
            "Invalid URI parts: {:?}, {:?}, {:?}",
            constructed_path, prefix, components
        ))
    })
}

impl<S, D, B, ResBody> HttpRepository<S, D, B, ResBody>
where
    S: Service<Request<B>, Response = Response<ResBody>> + Clone + Send + Sync + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync + 'static>> + Send + Sync + 'static,
    S::Future: Send + 'static,
    D: Pouf,
    B: Body + Default + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    ResBody: Body + Send + Unpin + 'static,
    ResBody::Data: AsRef<[u8]> + Send,
    ResBody::Error: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
{
    async fn get(&self, uri: &Uri) -> Result<Response<ResBody>> {
        let req = Request::builder()
            .uri(uri)
            .header("User-Agent", &*self.user_agent)
            .body(B::default())
            .map_err(|err| Error::Http {
                uri: uri.to_string(),
                err,
            })?;

        self.client
            .clone()
            .oneshot(req)
            .await
            .map_err(|err| Error::Repository {
                uri: uri.to_string(),
                err: err.into(),
            })
    }
}

impl<S, D, B, ResBody> RepositoryProvider<D> for HttpRepository<S, D, B, ResBody>
where
    S: Service<Request<B>, Response = Response<ResBody>> + Clone + Send + Sync + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync + 'static>> + Send + Sync + 'static,
    S::Future: Send + 'static,
    D: Pouf,
    B: Body + Default + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    ResBody: Body + Send + Unpin + 'static,
    ResBody::Data: AsRef<[u8]> + Send,
    ResBody::Error: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
{
    fn fetch_metadata<'a>(
        &'a self,
        meta_path: &MetadataPath,
        version: Option<MetadataVersion>,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncRead + Send + Unpin + 'a>>> {
        let meta_path = meta_path.clone();
        let components = meta_path.components::<D>(version);
        let uri = extend_uri(&self.uri, &self.metadata_prefix, &components);

        async move {
            // TODO(#278) check content length if known and fail early if the payload is too large.

            let uri = uri?;
            let resp = self.get(&uri).await?;

            let status = resp.status();
            if status == StatusCode::OK {
                let reader = EnforceMinimumBitrate::new(
                    resp.into_body()
                        .into_data_stream()
                        .map_err(io::Error::other)
                        .into_async_read(),
                    self.min_bytes_per_second,
                );

                let reader: Box<dyn AsyncRead + Send + Unpin> = Box::new(reader);
                Ok(reader)
            } else if status == StatusCode::NOT_FOUND {
                Err(Error::MetadataNotFound {
                    path: meta_path,
                    version,
                })
            } else {
                Err(Error::BadHttpStatus {
                    uri: uri.to_string(),
                    code: status,
                })
            }
        }
        .boxed()
    }

    fn fetch_target<'a>(
        &'a self,
        target_path: &TargetPath,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncRead + Send + Unpin + 'a>>> {
        let target_path = target_path.clone();
        let components = target_path.components();
        let uri = extend_uri(&self.uri, &self.targets_prefix, &components);

        async move {
            // TODO(#278) check content length if known and fail early if the payload is too large.

            let uri = uri?;
            let resp = self.get(&uri).await?;

            let status = resp.status();
            if status == StatusCode::OK {
                let reader = EnforceMinimumBitrate::new(
                    resp.into_body()
                        .into_data_stream()
                        .map_err(io::Error::other)
                        .into_async_read(),
                    self.min_bytes_per_second,
                );

                let reader: Box<dyn AsyncRead + Send + Unpin> = Box::new(reader);
                Ok(reader)
            } else if status == StatusCode::NOT_FOUND {
                Err(Error::TargetNotFound(target_path))
            } else {
                Err(Error::BadHttpStatus {
                    uri: uri.to_string(),
                    code: status,
                })
            }
        }
        .boxed()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // Old behavior of the `HttpRepository::get` extension
    // functionality
    #[test]
    fn http_repository_uri_construction() {
        let base_uri = "http://example.com/one";

        let prefix = Some(vec![String::from("prefix")]);
        let components = [
            String::from("components_one"),
            String::from("components_two"),
        ];

        let uri = base_uri.parse::<Uri>().unwrap();
        let extended_uri = extend_uri(&uri, &prefix, &components).unwrap();

        assert_eq!(
            extended_uri.to_string(),
            "http://example.com/one/prefix/components_one/components_two"
        );
    }

    #[test]
    fn http_repository_uri_construction_encoded() {
        let base_uri = "http://example.com/one";

        let prefix = Some(vec![String::from("prefix")]);
        let components = [String::from("chars to encode#?")];
        let uri = base_uri.parse::<Uri>().unwrap();
        let extended_uri = extend_uri(&uri, &prefix, &components)
            .expect("correctly generated a URI with a zone id");

        assert_eq!(
            extended_uri.to_string(),
            "http://example.com/one/prefix/chars%20to%20encode%23%3F"
        );
    }

    #[test]
    fn http_repository_uri_construction_no_components() {
        let base_uri = "http://example.com/one";

        let prefix = Some(vec![String::from("prefix")]);
        let components = [];

        let uri = base_uri.parse::<Uri>().unwrap();
        let extended_uri = extend_uri(&uri, &prefix, &components).unwrap();

        assert_eq!(extended_uri.to_string(), "http://example.com/one/prefix");
    }

    #[test]
    fn http_repository_uri_construction_no_prefix() {
        let base_uri = "http://example.com/one";

        let prefix = None;
        let components = [
            String::from("components_one"),
            String::from("components_two"),
        ];

        let uri = base_uri.parse::<Uri>().unwrap();
        let extended_uri = extend_uri(&uri, &prefix, &components).unwrap();

        assert_eq!(
            extended_uri.to_string(),
            "http://example.com/one/components_one/components_two"
        );
    }

    #[test]
    fn http_repository_uri_construction_with_query() {
        let base_uri = "http://example.com/one?test=1";

        let prefix = None;
        let components = [
            String::from("components_one"),
            String::from("components_two"),
        ];

        let uri = base_uri.parse::<Uri>().unwrap();
        let extended_uri = extend_uri(&uri, &prefix, &components).unwrap();

        assert_eq!(
            extended_uri.to_string(),
            "http://example.com/one/components_one/components_two?test=1"
        );
    }

    #[test]
    fn http_repository_uri_construction_ipv6_zoneid() {
        let base_uri = "http://[aaaa::aaaa:aaaa:aaaa:1234%252]:80";

        let prefix = Some(vec![String::from("prefix")]);
        let components = [
            String::from("componenents_one"),
            String::from("components_two"),
        ];
        let uri = base_uri.parse::<Uri>().unwrap();
        let extended_uri = extend_uri(&uri, &prefix, &components)
            .expect("correctly generated a URI with a zone id");
        assert_eq!(
            extended_uri.to_string(),
            "http://[aaaa::aaaa:aaaa:aaaa:1234%252]:80/prefix/componenents_one/components_two"
        );
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct MockServiceError(&'static str);

    impl std::fmt::Display for MockServiceError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl std::error::Error for MockServiceError {}

    #[derive(Clone)]
    struct ReadinessFailingService;

    impl<Req> Service<Req> for ReadinessFailingService {
        type Response = Response<hyper::body::Incoming>;
        type Error = MockServiceError;
        type Future = std::future::Ready<std::result::Result<Self::Response, Self::Error>>;

        fn poll_ready(
            &mut self,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
            std::task::Poll::Ready(Err(MockServiceError("simulated poll_ready error")))
        }

        fn call(&mut self, _req: Req) -> Self::Future {
            std::future::ready(Err(MockServiceError("should not be called")))
        }
    }

    #[derive(Clone)]
    struct CallFailingService;

    impl<Req> Service<Req> for CallFailingService {
        type Response = Response<hyper::body::Incoming>;
        type Error = MockServiceError;
        type Future = std::future::Ready<std::result::Result<Self::Response, Self::Error>>;

        fn poll_ready(
            &mut self,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: Req) -> Self::Future {
            std::future::ready(Err(MockServiceError("simulated call error")))
        }
    }

    #[derive(Clone)]
    struct CustomHeaderMiddleware<S> {
        inner: S,
    }

    impl<S, B> Service<Request<B>> for CustomHeaderMiddleware<S>
    where
        S: Service<Request<B>>,
    {
        type Response = S::Response;
        type Error = S::Error;
        type Future = S::Future;

        fn poll_ready(
            &mut self,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
            self.inner.poll_ready(cx)
        }

        fn call(&mut self, mut req: Request<B>) -> Self::Future {
            req.headers_mut()
                .insert("X-Custom-Tuf-Header", "test-middleware".parse().unwrap());
            self.inner.call(req)
        }
    }

    #[tokio::test]
    async fn http_repository_maps_service_poll_ready_error() {
        let repo = HttpRepositoryBuilder::<_, tuf::pouf::Pouf1>::new(
            Uri::from_static("http://example.com/repo"),
            ReadinessFailingService,
        )
        .build();

        let err = repo
            .fetch_metadata(&MetadataPath::root(), Some(MetadataVersion::ONE))
            .await
            .err()
            .expect("expected fetch_metadata to fail");

        match err {
            Error::Repository { uri, err } => {
                assert_eq!(uri, "http://example.com/repo/1.root.json");
                let mock_err = err
                    .downcast_ref::<MockServiceError>()
                    .expect("should be downcastable to MockServiceError");
                assert_eq!(mock_err, &MockServiceError("simulated poll_ready error"));
            }
            other => panic!("expected Error::Backend, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn http_repository_maps_service_call_error() {
        let repo = HttpRepositoryBuilder::<_, tuf::pouf::Pouf1>::new(
            Uri::from_static("http://example.com/repo"),
            CallFailingService,
        )
        .build();

        let err = repo
            .fetch_metadata(&MetadataPath::root(), Some(MetadataVersion::ONE))
            .await
            .err()
            .expect("expected fetch_metadata to fail");

        match err {
            Error::Repository { uri, err } => {
                assert_eq!(uri, "http://example.com/repo/1.root.json");
                let mock_err = err
                    .downcast_ref::<MockServiceError>()
                    .expect("should be downcastable to MockServiceError");
                assert_eq!(mock_err, &MockServiceError("simulated call error"));
            }
            other => panic!("expected Error::Backend, got {:?}", other),
        }
    }

    #[derive(Clone)]
    struct PendingReadinessService {
        polls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl<Req> Service<Req> for PendingReadinessService {
        type Response = Response<hyper::body::Incoming>;
        type Error = MockServiceError;
        type Future = std::future::Ready<std::result::Result<Self::Response, Self::Error>>;

        fn poll_ready(
            &mut self,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
            let count = self.polls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if count == 0 {
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            } else {
                std::task::Poll::Ready(Err(MockServiceError("ready after pending")))
            }
        }

        fn call(&mut self, _req: Req) -> Self::Future {
            std::future::ready(Err(MockServiceError("should not be called")))
        }
    }

    #[tokio::test]
    async fn http_repository_waits_for_poll_ready() {
        let polls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let repo = HttpRepositoryBuilder::<_, tuf::pouf::Pouf1>::new(
            Uri::from_static("http://example.com/repo"),
            PendingReadinessService {
                polls: polls.clone(),
            },
        )
        .build();

        let err = repo
            .fetch_metadata(&MetadataPath::root(), Some(MetadataVersion::ONE))
            .await
            .err()
            .expect("expected fetch_metadata to fail");

        match err {
            Error::Repository { uri, err } => {
                assert_eq!(uri, "http://example.com/repo/1.root.json");
                let mock_err = err
                    .downcast_ref::<MockServiceError>()
                    .expect("should be downcastable to MockServiceError");
                assert_eq!(mock_err, &MockServiceError("ready after pending"));
                assert_eq!(polls.load(std::sync::atomic::Ordering::SeqCst), 2);
            }
            other => panic!("expected Error::Backend, got {:?}", other),
        }
    }

    #[test]
    fn http_repository_accepts_custom_middleware_wrapper() {
        // Verify that wrapping an HTTP client with custom Tower middleware compiles and builds cleanly.
        let client =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build_http();
        let middleware = CustomHeaderMiddleware { inner: client };

        let _repo = HttpRepositoryBuilder::<_, tuf::pouf::Pouf1>::new(
            Uri::from_static("http://example.com/repo"),
            middleware,
        )
        .build();
    }

    #[derive(Clone)]
    struct MockResponseService {
        status: StatusCode,
        body: &'static [u8],
    }

    impl Service<Request<http_body_util::Empty<Bytes>>> for MockResponseService {
        type Response = Response<http_body_util::Full<Bytes>>;
        type Error = MockServiceError;
        type Future = std::future::Ready<std::result::Result<Self::Response, Self::Error>>;

        fn poll_ready(
            &mut self,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: Request<http_body_util::Empty<Bytes>>) -> Self::Future {
            let resp = Response::builder()
                .status(self.status)
                .body(http_body_util::Full::new(Bytes::from_static(self.body)))
                .unwrap();
            std::future::ready(Ok(resp))
        }
    }

    #[tokio::test]
    async fn http_repository_fetch_metadata_success() {
        use futures_util::io::AsyncReadExt;
        let repo = HttpRepositoryBuilder::<
            _,
            tuf::pouf::Pouf1,
            http_body_util::Empty<Bytes>,
            http_body_util::Full<Bytes>,
        >::new_with_body(
            Uri::from_static("http://example.com/repo"),
            MockResponseService {
                status: StatusCode::OK,
                body: b"root metadata payload",
            },
        )
        .build();

        let mut reader = repo
            .fetch_metadata(&MetadataPath::root(), Some(MetadataVersion::ONE))
            .await
            .expect("expected fetch_metadata to succeed");
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"root metadata payload");
    }

    #[tokio::test]
    async fn http_repository_fetch_target_success() {
        use futures_util::io::AsyncReadExt;
        let repo = HttpRepositoryBuilder::<
            _,
            tuf::pouf::Pouf1,
            http_body_util::Empty<Bytes>,
            http_body_util::Full<Bytes>,
        >::new_with_body(
            Uri::from_static("http://example.com/repo"),
            MockResponseService {
                status: StatusCode::OK,
                body: b"target binary data",
            },
        )
        .build();

        let mut reader = repo
            .fetch_target(&TargetPath::new("foo/bar.bin").unwrap())
            .await
            .expect("expected fetch_target to succeed");
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"target binary data");
    }

    #[tokio::test]
    async fn http_repository_fetch_metadata_not_found() {
        let repo = HttpRepositoryBuilder::<
            _,
            tuf::pouf::Pouf1,
            http_body_util::Empty<Bytes>,
            http_body_util::Full<Bytes>,
        >::new_with_body(
            Uri::from_static("http://example.com/repo"),
            MockResponseService {
                status: StatusCode::NOT_FOUND,
                body: b"",
            },
        )
        .build();

        let err = repo
            .fetch_metadata(&MetadataPath::root(), Some(MetadataVersion::ONE))
            .await
            .err()
            .expect("expected fetch_metadata to fail");

        match err {
            Error::MetadataNotFound { path, version } => {
                assert_eq!(path, MetadataPath::root());
                assert_eq!(version, Some(MetadataVersion::ONE));
            }
            other => panic!("expected Error::MetadataNotFound, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn http_repository_fetch_target_not_found() {
        let target_path = TargetPath::new("missing.tar.gz").unwrap();
        let repo = HttpRepositoryBuilder::<
            _,
            tuf::pouf::Pouf1,
            http_body_util::Empty<Bytes>,
            http_body_util::Full<Bytes>,
        >::new_with_body(
            Uri::from_static("http://example.com/repo"),
            MockResponseService {
                status: StatusCode::NOT_FOUND,
                body: b"",
            },
        )
        .build();

        let err = repo
            .fetch_target(&target_path)
            .await
            .err()
            .expect("expected fetch_target to fail");

        match err {
            Error::TargetNotFound(path) => {
                assert_eq!(path, target_path);
            }
            other => panic!("expected Error::TargetNotFound, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn http_repository_fetch_bad_http_status() {
        let repo = HttpRepositoryBuilder::<
            _,
            tuf::pouf::Pouf1,
            http_body_util::Empty<Bytes>,
            http_body_util::Full<Bytes>,
        >::new_with_body(
            Uri::from_static("http://example.com/repo"),
            MockResponseService {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                body: b"",
            },
        )
        .build();

        let err_meta = repo
            .fetch_metadata(&MetadataPath::root(), Some(MetadataVersion::ONE))
            .await
            .err()
            .expect("expected fetch_metadata to fail on 500");
        match err_meta {
            Error::BadHttpStatus { uri, code } => {
                assert_eq!(uri, "http://example.com/repo/1.root.json");
                assert_eq!(code, StatusCode::INTERNAL_SERVER_ERROR);
            }
            other => panic!("expected Error::BadHttpStatus, got {:?}", other),
        }

        let err_target = repo
            .fetch_target(&TargetPath::new("file.dat").unwrap())
            .await
            .err()
            .expect("expected fetch_target to fail on 500");
        match err_target {
            Error::BadHttpStatus { uri, code } => {
                assert_eq!(uri, "http://example.com/repo/file.dat");
                assert_eq!(code, StatusCode::INTERNAL_SERVER_ERROR);
            }
            other => panic!("expected Error::BadHttpStatus, got {:?}", other),
        }
    }

    #[derive(Clone)]
    struct HeaderCheckingService {
        expected_header: &'static str,
        expected_value: &'static str,
    }

    impl Service<Request<http_body_util::Empty<Bytes>>> for HeaderCheckingService {
        type Response = Response<http_body_util::Full<Bytes>>;
        type Error = MockServiceError;
        type Future = std::future::Ready<std::result::Result<Self::Response, Self::Error>>;

        fn poll_ready(
            &mut self,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: Request<http_body_util::Empty<Bytes>>) -> Self::Future {
            if let Some(val) = req.headers().get(self.expected_header)
                && val == self.expected_value
            {
                let resp = Response::builder()
                    .status(StatusCode::OK)
                    .body(http_body_util::Full::new(Bytes::from_static(b"ok")))
                    .unwrap();
                return std::future::ready(Ok(resp));
            }
            std::future::ready(Err(MockServiceError("header check failed")))
        }
    }

    #[tokio::test]
    async fn http_repository_custom_middleware_wrapper_inserts_header() {
        use futures_util::io::AsyncReadExt;
        let inner = HeaderCheckingService {
            expected_header: "X-Custom-Tuf-Header",
            expected_value: "test-middleware",
        };
        let middleware = CustomHeaderMiddleware { inner };

        let repo = HttpRepositoryBuilder::<
            _,
            tuf::pouf::Pouf1,
            http_body_util::Empty<Bytes>,
            http_body_util::Full<Bytes>,
        >::new_with_body(Uri::from_static("http://example.com/repo"), middleware)
        .build();

        let mut reader = repo
            .fetch_metadata(&MetadataPath::root(), Some(MetadataVersion::ONE))
            .await
            .expect("should succeed with injected header");
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"ok");
    }

    #[test]
    fn http_repository_builder_constructors() {
        let client = MockResponseService {
            status: StatusCode::OK,
            body: b"",
        };
        let uri = Uri::from_static("http://example.com/tuf");
        let builder1 = HttpRepositoryBuilder::<
            _,
            tuf::pouf::Pouf1,
            http_body_util::Empty<Bytes>,
            http_body_util::Full<Bytes>,
        >::new(uri.clone(), client.clone())
        .user_agent("test-client/1.0")
        .metadata_prefix(vec!["meta".into()])
        .targets_prefix(vec!["targets".into()])
        .min_bytes_per_second(1024);
        let repo1 = builder1.build();
        assert_eq!(repo1.user_agent, "test-client/1.0");
        assert_eq!(repo1.min_bytes_per_second, 1024);

        let builder2 = HttpRepositoryBuilder::<
            _,
            tuf::pouf::Pouf1,
            http_body_util::Empty<Bytes>,
            http_body_util::Full<Bytes>,
        >::new_with_body(uri, client.clone());
        let repo2 = builder2.build();
        assert_eq!(repo2.user_agent, "rust-tuf");

        let builder3 = HttpRepositoryBuilder::<
            _,
            tuf::pouf::Pouf1,
            http_body_util::Empty<Bytes>,
            http_body_util::Full<Bytes>,
        >::new_with_body(Uri::from_static("http://example.com/tuf"), client);
        let _repo3 = builder3.build();
    }
}
