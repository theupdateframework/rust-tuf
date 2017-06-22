use hyper::Url;
use hyper::client::Client as HttpClient;
use hyper::client::response::Response;
use hyper::header::{Headers, UserAgent};

use error::Error;
use util;

pub fn get(http_client: &HttpClient, url: &Url) -> Result<Response, Error> {
    let mut headers = Headers::new();
    headers.set(UserAgent(format!("rust-tuf/{}", env!("CARGO_PKG_VERSION"))));
    let req = http_client.get(url.clone())
        .headers(headers);
    Ok(req.send()?)
}
