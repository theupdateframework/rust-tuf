use hyper;
use std::path::{Path, PathBuf};
use url::Url;
use url::percent_encoding::{percent_encode, percent_decode, DEFAULT_ENCODE_SET};

use error::Error;

pub fn path_to_url(path: &Path) -> Result<Url, Error> {
    path.to_str()
        .ok_or(Error::Generic("Path was not utf-8".to_string()))
        .and_then(|path_str| {
            // TODO windows support
            Url::parse(&format!("file://{}",
                                percent_encode(path_str.as_bytes(), DEFAULT_ENCODE_SET)))
                .map_err(|e| Error::Generic(format!("{}", e)))
        })
}

pub fn url_path_to_os_path(url_path: &str) -> Result<PathBuf, Error> {
    // TODO windows support
    let url_path = percent_decode(url_path.as_bytes())
        .decode_utf8()
        .map_err(|e| Error::Generic(format!("{}", e)))?
        .into_owned();

    Ok(Path::new(&url_path).to_path_buf())
}

pub fn url_to_hyper_url(url: &Url) -> Result<hyper::Url, Error> {
    Ok(hyper::Url::parse(url.as_str())?)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn test_path_to_url_nix() {
        let path = Path::new("/tmp/test");
        assert_eq!(path_to_url(path),
                   Ok(Url::parse("file:///tmp/test").unwrap()));

        let path = Path::new("/tmp/test stuff");
        assert_eq!(path_to_url(path),
                   Ok(Url::parse("file:///tmp/test%20stuff").unwrap()));
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_path_to_url_win() {
        // TODO someone else needs to review this to make sure I'm not an idiot

        let path = Path::new("\\tmp\\test");
        assert_eq!(path_to_url(path),
                   Ok(Url::parse("file:///tmp/test").unwrap()));

        let path = Path::new("\\tmp\\test stuff");
        assert_eq!(path_to_url(path),
                   Ok(Url::parse("file:///tmp/test%20stuff").unwrap()));

        let path = Path::new("C:\\\\tmp\\test stuff");
        assert_eq!(path_to_url(path),
                   Ok(Url::parse("file:///C://tmp/test%20stuff").unwrap()));
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn test_url_path_to_os_path_nix() {
        let path = "/tmp/test";
        assert_eq!(url_path_to_os_path(path), Ok(PathBuf::from("/tmp/test")));

        let path = "/tmp/test%20stuff";
        assert_eq!(url_path_to_os_path(path),
                   Ok(PathBuf::from("/tmp/test stuff")));
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_url_path_to_os_path_win() {
        // TODO someone else needs to review this to make sure I'm not an idiot

        let path = "C:\\\\tmp\\test";
        assert_eq!(url_path_to_os_path(path),
                   Ok(PathBuf::from("C:\\\\tmp\\test")));

        let path = "C:\\\\tmp\\test%20stuff";
        assert_eq!(url_path_to_os_path(path),
                   Ok(PathBuf::from("C:\\\\tmp\\test stuff")));
    }
}
