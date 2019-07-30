use chrono::offset::Utc;
use chrono::DateTime;
use futures::io::AsyncRead;
use futures::{ready, Poll};
use ring::digest::{self, SHA256, SHA512};
use std::io::{self, ErrorKind};
use std::marker::Unpin;
use std::pin::Pin;
use std::task::Context;

use crate::crypto::{HashAlgorithm, HashValue};
use crate::error::Error;
use crate::Result;

/// Wrapper to verify a byte stream as it is read.
///
/// Wraps a `Read` to ensure that the consumer can't read more than a capped maximum number of
/// bytes. Also, this ensures that a minimum bitrate and returns an `Err` if it is not. Finally,
/// when the underlying `Read` is fully consumed, the hash of the data is optionally calculated. If
/// the calculated hash does not match the given hash, it will return an `Err`. Consumers of a
/// `SafeReader` should purge and untrust all read bytes if this ever returns an `Err`.
///
/// It is **critical** that none of the bytes from this struct are used until it has been fully
/// consumed as the data is untrusted.
pub struct SafeReader<R> {
    inner: R,
    max_size: u64,
    min_bytes_per_second: u32,
    hasher: Option<(digest::Context, HashValue)>,
    start_time: Option<DateTime<Utc>>,
    bytes_read: u64,
}

impl<R: AsyncRead> SafeReader<R> {
    /// Create a new `SafeReader`.
    ///
    /// The argument `hash_data` takes a `HashAlgorithm` and expected `HashValue`. The given
    /// algorithm is used to hash the data as it is read. At the end of the stream, the digest is
    /// calculated and compared against `HashValue`. If the two are not equal, it means the data
    /// stream has been tampered with in some way.
    pub fn new(
        read: R,
        max_size: u64,
        min_bytes_per_second: u32,
        hash_data: Option<(&HashAlgorithm, HashValue)>,
    ) -> Result<Self> {
        let hasher = match hash_data {
            Some((alg, value)) => {
                let ctx = match *alg {
                    HashAlgorithm::Sha256 => digest::Context::new(&SHA256),
                    HashAlgorithm::Sha512 => digest::Context::new(&SHA512),
                    HashAlgorithm::Unknown(ref s) => {
                        return Err(Error::IllegalArgument(format!(
                            "Unknown hash algorithm: {}",
                            s
                        )));
                    }
                };
                Some((ctx, value))
            }
            None => None,
        };

        Ok(SafeReader {
            inner: read,
            max_size,
            min_bytes_per_second,
            hasher,
            start_time: None,
            bytes_read: 0,
        })
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for SafeReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let read_bytes = ready!(Pin::new(&mut self.inner).poll_read(cx, buf))?;

        if self.start_time.is_none() {
            self.start_time = Some(Utc::now())
        }

        if read_bytes == 0 {
            if let Some((context, expected_hash)) = self.hasher.take() {
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

        let duration = Utc::now().signed_duration_since(self.start_time.unwrap());
        // 30 second grace period before we start checking the bitrate
        if duration.num_seconds() >= 30 {
            if (self.bytes_read as f32) / (duration.num_seconds() as f32)
                < self.min_bytes_per_second as f32
            {
                return Poll::Ready(Err(io::Error::new(
                    ErrorKind::TimedOut,
                    "Read aborted. Bitrate too low.",
                )));
            }
        }

        if let Some((ref mut context, _)) = self.hasher {
            context.update(&buf[..(read_bytes)]);
        }

        Poll::Ready(Ok(read_bytes))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use futures::executor::block_on;
    use futures::io::AsyncReadExt;

    #[test]
    fn valid_read() {
        block_on(async {
            let bytes: &[u8] = &[0x00, 0x01, 0x02, 0x03];
            let mut reader = SafeReader::new(bytes, bytes.len() as u64, 0, None).unwrap();
            let mut buf = Vec::new();
            assert!(reader.read_to_end(&mut buf).await.is_ok());
            assert_eq!(buf, bytes);
        })
    }

    #[test]
    fn valid_read_large_data() {
        block_on(async {
            let bytes: &[u8] = &[0x00; 64 * 1024];
            let mut reader = SafeReader::new(bytes, bytes.len() as u64, 0, None).unwrap();
            let mut buf = Vec::new();
            assert!(reader.read_to_end(&mut buf).await.is_ok());
            assert_eq!(buf, bytes);
        })
    }

    #[test]
    fn valid_read_below_max_size() {
        block_on(async {
            let bytes: &[u8] = &[0x00, 0x01, 0x02, 0x03];
            let mut reader = SafeReader::new(bytes, (bytes.len() as u64) + 1, 0, None).unwrap();
            let mut buf = Vec::new();
            assert!(reader.read_to_end(&mut buf).await.is_ok());
            assert_eq!(buf, bytes);
        })
    }

    #[test]
    fn invalid_read_above_max_size() {
        block_on(async {
            let bytes: &[u8] = &[0x00, 0x01, 0x02, 0x03];
            let mut reader = SafeReader::new(bytes, (bytes.len() as u64) - 1, 0, None).unwrap();
            let mut buf = Vec::new();
            assert!(reader.read_to_end(&mut buf).await.is_err());
        })
    }

    #[test]
    fn invalid_read_above_max_size_large_data() {
        block_on(async {
            let bytes: &[u8] = &[0x00; 64 * 1024];
            let mut reader = SafeReader::new(bytes, (bytes.len() as u64) - 1, 0, None).unwrap();
            let mut buf = Vec::new();
            assert!(reader.read_to_end(&mut buf).await.is_err());
        })
    }

    #[test]
    fn valid_read_good_hash() {
        block_on(async {
            let bytes: &[u8] = &[0x00, 0x01, 0x02, 0x03];
            let mut context = digest::Context::new(&SHA256);
            context.update(&bytes);
            let hash_value = HashValue::new(context.finish().as_ref().to_vec());
            let mut reader = SafeReader::new(
                bytes,
                bytes.len() as u64,
                0,
                Some((&HashAlgorithm::Sha256, hash_value)),
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
            context.update(&bytes);
            context.update(&[0xFF]); // evil bytes
            let hash_value = HashValue::new(context.finish().as_ref().to_vec());
            let mut reader = SafeReader::new(
                bytes,
                bytes.len() as u64,
                0,
                Some((&HashAlgorithm::Sha256, hash_value)),
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
            context.update(&bytes);
            let hash_value = HashValue::new(context.finish().as_ref().to_vec());
            let mut reader = SafeReader::new(
                bytes,
                bytes.len() as u64,
                0,
                Some((&HashAlgorithm::Sha256, hash_value)),
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
            context.update(&bytes);
            context.update(&[0xFF]); // evil bytes
            let hash_value = HashValue::new(context.finish().as_ref().to_vec());
            let mut reader = SafeReader::new(
                bytes,
                bytes.len() as u64,
                0,
                Some((&HashAlgorithm::Sha256, hash_value)),
            )
            .unwrap();
            let mut buf = Vec::new();
            assert!(reader.read_to_end(&mut buf).await.is_err());
        })
    }
}
