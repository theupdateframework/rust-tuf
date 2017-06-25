use std::fs::{self, File};
use std::io::{self, Read, Write, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use url::percent_encoding::percent_decode;
use uuid::Uuid;

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
            .map_err(|e| {
                Error::Generic(format!("Path component not utf-8: {:?}", e))
            })?
            .into_owned();
        out.push(component);
    }
    Ok(out)
}


#[derive(Debug)]
struct TempFileInner {
    path: PathBuf,
    file: File,
}

#[derive(Debug)]
pub struct TempFile(Option<TempFileInner>);

impl TempFile {
    pub fn new(prefix: PathBuf) -> Result<Self, io::Error> {
        let path = prefix.join(Uuid::new_v4().hyphenated().to_string());
        Ok(TempFile(Some(TempFileInner {
            path: path.clone(),
            file: File::create(path)?,
        })))
    }

    pub fn from_existing(path: PathBuf) -> Result<Self, io::Error> {
        Ok(TempFile(Some(TempFileInner {
            path: path.clone(),
            file: File::open(path)?,
        })))
    }

    pub fn file_mut(&mut self) -> Result<&mut File, io::Error> {
        match self.0 {
            Some(ref mut inner) => Ok(&mut inner.file),
            None => Err(io::Error::new(
                io::ErrorKind::Other,
                "invalid TempFile reference",
            )),
        }
    }

    pub fn persist(mut self, dest: &Path) -> Result<(), io::Error> {
        match self.0.take() {
            Some(inner) => fs::rename(inner.path, dest),
            None => Err(io::Error::new(
                io::ErrorKind::Other,
                "invalid TempFile reference",
            )),
        }
    }
}

impl Write for TempFile {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        self.file_mut()?.write(buf)
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        self.file_mut()?.flush()
    }
}

impl Read for TempFile {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        self.file_mut()?.read(buf)
    }
}

impl Seek for TempFile {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64, io::Error> {
        self.file_mut()?.seek(pos)
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        match self.0.take() {
            Some(inner) => {
                drop(inner.file);
                match fs::remove_file(inner.path) {
                    Ok(()) => (),
                    Err(e) => warn!("Failed to delete tempfile: {:?}", e),
                }
            }
            None => (),
        }
    }
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
        assert_eq!(
            url_path_to_os_path(path),
            Ok(PathBuf::from("/tmp/test stuff"))
        );
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
        assert_eq!(
            url_path_to_os_path(path),
            Ok(PathBuf::from(r"C:\tmp\test stuff"))
        );
    }

    #[test]
    fn test_url_path_to_path_components() {
        let path = "test/foo";
        assert_eq!(
            url_path_to_path_components(path),
            Ok(vec!["test".into(), "foo".into()])
        );

        let path = "test/foo%20bar";
        assert_eq!(
            url_path_to_path_components(path),
            Ok(vec!["test".into(), "foo bar".into()])
        );
    }
}
