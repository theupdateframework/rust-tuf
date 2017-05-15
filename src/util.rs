//! Convenience helpers. Intended for internal use only, but made public for testing.

use env_logger::LogBuilder;
use hyper;
use std::path::{Path, PathBuf, Component};
use url::Url;
use url::percent_encoding::{percent_encode, percent_decode, DEFAULT_ENCODE_SET};

use error::Error;

// TODO I'm pretty sure all of this path stuff is a mess, but at least the basics of
// windows will work, right? Right?

/// Converts a `Path` into a URL with scheme `file://`.
pub fn path_to_url(path: &Path) -> Result<Url, Error> {
    // TODO handle sloppy to_string_lossy() calls

    let path_str = path.components()
        .fold(PathBuf::new(), |buf, c| match c {
            Component::Normal(os_str) => {
                buf.join(format!("{}",
                                 percent_encode(os_str.to_string_lossy().as_bytes(),
                                                DEFAULT_ENCODE_SET)))
            }
            Component::RootDir => buf.join("/"),
            Component::Prefix(pref) => {
                if cfg!(windows) {
                    buf.join(pref.as_os_str().to_string_lossy().into_owned())
                } else {
                    buf
                }
            }
            Component::CurDir => buf.join("."),
            Component::ParentDir => buf.join(".."),
        });

    Url::parse(&format!("file://{}",
                        percent_encode(path_str.to_string_lossy().as_bytes(), DEFAULT_ENCODE_SET)))
        .map_err(|e| Error::Generic(format!("{}", e)))
}

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

/// Converts a `url::Url` into a `hyper::Url`.
pub fn url_to_hyper_url(url: &Url) -> Result<hyper::Url, Error> {
    Ok(hyper::Url::parse(url.as_str())?)
}

/// Initialize the logger used for testing.
pub fn test_logger() {
    let _ = LogBuilder::new()
        // TODO requires new release of env_logger .target(LogTarget::Stdout)
        .init();
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
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn test_path_to_url_spaces_nix() {
        let path = Path::new("/tmp/test stuff");
        assert_eq!(path_to_url(path),
                   Ok(Url::parse("file:///tmp/test%20stuff").unwrap()));
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_path_to_url_win() {
        let path = Path::new(r"C:\tmp\test");
        assert_eq!(path_to_url(path),
                   Ok(Url::parse("file:///C:/tmp/test").unwrap()));
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_path_to_url_spaces_win() {
        let path = Path::new(r"C:\tmp\test stuff");
        assert_eq!(path_to_url(path),
                   Ok(Url::parse("file:///C:/tmp/test%20stuff").unwrap()));
    }

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
}
