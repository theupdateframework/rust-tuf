use hyper::client::Client as HttpClient;
use hyper::client::response::Response;
use hyper::header::{Headers, UserAgent};
use url::Url;

use error::Error;
use util;

pub fn get(http_client: &HttpClient, url: &Url) -> Result<Response, Error> {
    let mut headers = Headers::new();
    headers.set(UserAgent(format!("rust-tuf/{}", env!("CARGO_PKG_VERSION"))));
    let req = http_client.get(util::url_to_hyper_url(url)?)
        .headers(headers);
    Ok(req.send()?)
}
