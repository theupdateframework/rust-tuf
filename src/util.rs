use hyper;
use std::path::{Path, PathBuf};
use url::Url;
use url::percent_encoding::percent_decode;

use error::Error;

/// Converts a URL string (without scheme) into an OS specific path.
pub fn url_path_to_os_path(url_path: &str) -> Result<PathBuf, Error> {
    let url_path = if cfg!(os = "windows") {
        url_path.replace("/", r"\")
    } else {
        url_path.to_string()
    };

    let url_path = percent_decode(url_path.as_bytes())
        .decode_utf8()
        .map_err(|e| Error::Generic(format!("{}", e)))?
        .into_owned();

    Ok(Path::new(&url_path).to_path_buf())
}

pub fn url_path_to_path_components(url_path: &str) -> Result<Vec<String>, Error> {
    let mut out = Vec::new();
    for component in url_path.split("/") {
        let component = percent_decode(component.as_bytes())
            .decode_utf8()
            .map_err(|e| Error::Generic(format!("Path component not utf-8: {:?}", e)))?
            .into_owned();
        out.push(component);
    }
    Ok(out)
}

/// Converts a `url::Url` into a `hyper::Url`.
pub fn url_to_hyper_url(url: &Url) -> Result<hyper::Url, Error> {
    Ok(hyper::Url::parse(url.as_str())?)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn test_url_path_to_os_path_nix() {
        let path = "/tmp/test";
        assert_eq!(url_path_to_os_path(path), Ok(PathBuf::from("/tmp/test")));
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn test_url_path_to_os_path_percent_nix() {
        let path = "/tmp/test%20stuff";
        assert_eq!(url_path_to_os_path(path),
                   Ok(PathBuf::from("/tmp/test stuff")));
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_url_path_to_os_path_win() {
        let path = r"C:/tmp/test";
        assert_eq!(url_path_to_os_path(path), Ok(PathBuf::from(r"C:\tmp\test")));
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_url_path_to_os_path_spaces_win() {
        let path = r"C:/tmp/test%20stuff";
        assert_eq!(url_path_to_os_path(path),
                   Ok(PathBuf::from(r"C:\tmp\test stuff")));
    }

    #[test]
    fn test_url_path_to_path_components() {
        let path = "test/foo";
        assert_eq!(url_path_to_path_components(path),
                   Ok(vec!["test".into(), "foo".into()]));

        let path = "test/foo%20bar";
        assert_eq!(url_path_to_path_components(path),
                   Ok(vec!["test".into(), "foo bar".into()]));
    }
}
