use futures_io::AsyncRead;
use futures_util::ready;
use ring::digest;
use std::io::{self, ErrorKind};
use std::marker::Unpin;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::Result;
use crate::crypto::{HashAlgorithm, HashValue};

/// Wrapper to verify a byte stream as it is read.
///
/// Wraps an `AsyncRead` to ensure that the consumer can't read more than a capped maximum number of
/// bytes. Also, when the underlying `AsyncRead` is fully consumed, the hash of the data is
/// optionally calculated. If the calculated hash does not match the given hash, it will return an
/// `Err`. Consumers of a `SafeReader` should purge and untrust all read bytes if this ever returns
/// an `Err`.
///
/// It is **critical** that none of the bytes from this struct are used until it has been fully
/// consumed as the data is untrusted.
pub(crate) struct EnforceSizeAndHash<R> {
    inner: R,
    max_size: u64,
    hashers: Vec<(digest::Context, HashValue)>,
    bytes_read: u64,
}

impl<R: AsyncRead> EnforceSizeAndHash<R> {
    /// Create a new `SafeReader`.
    ///
    /// The argument `hash_data` takes a `HashAlgorithm` and expected `HashValue`. The given
    /// algorithm is used to hash the data as it is read. At the end of the stream, the digest is
    /// calculated and compared against `HashValue`. If the two are not equal, it means the data
    /// stream has been corrupted or tampered with in some way.
    pub(crate) fn new(
        read: R,
        max_size: u64,
        hash_data: Vec<(&'static HashAlgorithm, HashValue)>,
    ) -> Result<Self> {
        let mut hashers = Vec::with_capacity(hash_data.len());
        for (alg, value) in hash_data {
            hashers.push((alg.digest_context()?, value));
        }

        Ok(EnforceSizeAndHash {
            inner: read,
            max_size,
            hashers,
            bytes_read: 0,
        })
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for EnforceSizeAndHash<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let read_bytes = ready!(Pin::new(&mut self.inner).poll_read(cx, buf))?;

        if read_bytes == 0 {
            for (context, expected_hash) in self.hashers.drain(..) {
                let generated_hash = context.finish();
                if generated_hash.as_ref() != expected_hash.value() {
                    return Poll::Ready(Err(io::Error::new(
                        ErrorKind::InvalidData,
                        "Calculated hash did not match the required hash.",
                    )));
                }
            }

            return Poll::Ready(Ok(0));
        }

        match self.bytes_read.checked_add(read_bytes as u64) {
            Some(sum) if sum <= self.max_size => self.bytes_read = sum,
            _ => {
                return Poll::Ready(Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "Read exceeded the maximum allowed bytes.",
                )));
            }
        }

        for (context, _) in &mut self.hashers {
            context.update(&buf[..read_bytes]);
        }

        Poll::Ready(Ok(read_bytes))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use futures_executor::block_on;
    use futures_util::io::AsyncReadExt;
    use ring::digest::SHA256;

    #[test]
    fn valid_read() {
        block_on(async {
            let bytes: &[u8] = &[0x00, 0x01, 0x02, 0x03];
            let mut reader = EnforceSizeAndHash::new(bytes, bytes.len() as u64, vec![]).unwrap();
            let mut buf = Vec::new();
            assert!(reader.read_to_end(&mut buf).await.is_ok());
            assert_eq!(buf, bytes);
        })
    }

    #[test]
    fn valid_read_large_data() {
        block_on(async {
            let bytes: &[u8] = &[0x00; 64 * 1024];
            let mut reader = EnforceSizeAndHash::new(bytes, bytes.len() as u64, vec![]).unwrap();
            let mut buf = Vec::new();
            assert!(reader.read_to_end(&mut buf).await.is_ok());
            assert_eq!(buf, bytes);
        })
    }

    #[test]
    fn valid_read_below_max_size() {
        block_on(async {
            let bytes: &[u8] = &[0x00, 0x01, 0x02, 0x03];
            let mut reader =
                EnforceSizeAndHash::new(bytes, (bytes.len() as u64) + 1, vec![]).unwrap();
            let mut buf = Vec::new();
            assert!(reader.read_to_end(&mut buf).await.is_ok());
            assert_eq!(buf, bytes);
        })
    }

    #[test]
    fn invalid_read_above_max_size() {
        block_on(async {
            let bytes: &[u8] = &[0x00, 0x01, 0x02, 0x03];
            let mut reader =
                EnforceSizeAndHash::new(bytes, (bytes.len() as u64) - 1, vec![]).unwrap();
            let mut buf = Vec::new();
            assert!(reader.read_to_end(&mut buf).await.is_err());
        })
    }

    #[test]
    fn invalid_read_above_max_size_large_data() {
        block_on(async {
            let bytes: &[u8] = &[0x00; 64 * 1024];
            let mut reader =
                EnforceSizeAndHash::new(bytes, (bytes.len() as u64) - 1, vec![]).unwrap();
            let mut buf = Vec::new();
            assert!(reader.read_to_end(&mut buf).await.is_err());
        })
    }

    #[test]
    fn valid_read_good_hash() {
        block_on(async {
            let bytes: &[u8] = &[0x00, 0x01, 0x02, 0x03];
            let mut context = digest::Context::new(&SHA256);
            context.update(bytes);
            let hash_value = HashValue::new(context.finish().as_ref().to_vec());
            let mut reader = EnforceSizeAndHash::new(
                bytes,
                bytes.len() as u64,
                vec![(&HashAlgorithm::Sha256, hash_value)],
            )
            .unwrap();
            let mut buf = Vec::new();
            assert!(reader.read_to_end(&mut buf).await.is_ok());
            assert_eq!(buf, bytes);
        })
    }

    #[test]
    fn invalid_read_bad_hash() {
        block_on(async {
            let bytes: &[u8] = &[0x00, 0x01, 0x02, 0x03];
            let mut context = digest::Context::new(&SHA256);
            context.update(bytes);
            context.update(&[0xFF]); // evil bytes
            let hash_value = HashValue::new(context.finish().as_ref().to_vec());
            let mut reader = EnforceSizeAndHash::new(
                bytes,
                bytes.len() as u64,
                vec![(&HashAlgorithm::Sha256, hash_value)],
            )
            .unwrap();
            let mut buf = Vec::new();
            assert!(reader.read_to_end(&mut buf).await.is_err());
        })
    }

    #[test]
    fn valid_read_good_hash_large_data() {
        block_on(async {
            let bytes: &[u8] = &[0x00; 64 * 1024];
            let mut context = digest::Context::new(&SHA256);
            context.update(bytes);
            let hash_value = HashValue::new(context.finish().as_ref().to_vec());
            let mut reader = EnforceSizeAndHash::new(
                bytes,
                bytes.len() as u64,
                vec![(&HashAlgorithm::Sha256, hash_value)],
            )
            .unwrap();
            let mut buf = Vec::new();
            assert!(reader.read_to_end(&mut buf).await.is_ok());
            assert_eq!(buf, bytes);
        })
    }

    #[test]
    fn invalid_read_bad_hash_large_data() {
        block_on(async {
            let bytes: &[u8] = &[0x00; 64 * 1024];
            let mut context = digest::Context::new(&SHA256);
            context.update(bytes);
            context.update(&[0xFF]); // evil bytes
            let hash_value = HashValue::new(context.finish().as_ref().to_vec());
            let mut reader = EnforceSizeAndHash::new(
                bytes,
                bytes.len() as u64,
                vec![(&HashAlgorithm::Sha256, hash_value)],
            )
            .unwrap();
            let mut buf = Vec::new();
            assert!(reader.read_to_end(&mut buf).await.is_err());
        })
    }
}
