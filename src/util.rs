use bytes::Bytes;
use chrono::offset::Utc;
use chrono::DateTime;
use futures::{Async, Future, Poll, Stream, future, stream};
use ring::digest::{self, SHA256, SHA512};
use std::io::{self, ErrorKind};

use crypto::{HashAlgorithm, HashValue};
use error::Error;
use Result;

/// Wrapper to verify a byte stream as it is read.
///
/// Wraps a `Stream` to ensure that the consumer can't read more than a capped maximum number of
/// bytes. Also, this ensures that a minimum bitrate and returns an `Err` if it is not. Finally,
/// when the underlying `Read` is fully consumed, the hash of the data is optionally calculated. If
/// the calculated hash does not match the given hash, it will return an `Err`. Consumers of a
/// `SafeReader` should purge and untrust all read bytes if this ever returns an `Err`.
///
/// It is **critical** that none of the bytes from this struct are used until it has been fully
/// consumed as the data is untrusted.
pub trait SafeStreamExt: Stream<Item = Bytes, Error = Error> + Sized {
    /// Wrap a byte stream.
    fn safe_stream(
        self,
        max_size: u64,
        min_bytes_per_second: u32,
        hash_data: Option<(&HashAlgorithm, HashValue)>,
    ) -> Result<SafeStream<Self>> {
        SafeStream::new(self, max_size, min_bytes_per_second, hash_data)
    }
}

impl<T: Stream<Item = Bytes, Error = Error>> SafeStreamExt for T {}

/// Wrapper to verify a byte stream as it is read.
///
/// Wraps a `Stream` to ensure that the consumer can't read more than a capped maximum number of
/// bytes. Also, this ensures that a minimum bitrate and returns an `Err` if it is not. Finally,
/// when the underlying `Read` is fully consumed, the hash of the data is optionally calculated. If
/// the calculated hash does not match the given hash, it will return an `Err`. Consumers of a
/// `SafeReader` should purge and untrust all read bytes if this ever returns an `Err`.
///
/// It is **critical** that none of the bytes from this struct are used until it has been fully
/// consumed as the data is untrusted.
pub struct SafeStream<T: Stream<Item = Bytes, Error = Error>> {
    inner: T,
    hasher: SafeHasher,
}

impl<T: Stream<Item = Bytes, Error = Error>> SafeStream<T> {
    /// Create a new `SafeStream`.
    ///
    /// The argument `hash_data` takes a `HashAlgorithm` and expected `HashValue`. The given
    /// algorithm is used to hash the data as it is read. At the end of the stream, the digest is
    /// calculated and compared against `HashValue`. If the two are not equal, it means the data
    /// stream has been tampered with in some way.
    pub fn new(
        stream: T,
        max_size: u64,
        min_bytes_per_second: u32,
        hash_data: Option<(&HashAlgorithm, HashValue)>,
    ) -> Result<Self> {
        let hasher = SafeHasher::new(max_size, min_bytes_per_second, hash_data)?;

        Ok(SafeStream {
            inner: stream,
            hasher: hasher,
        })
    }
}

impl<T: Stream<Item = Bytes, Error = Error>> Stream for SafeStream<T> {
    type Item = Bytes;
    type Error = Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        if let Some(bytes) = try_ready!(self.inner.poll()) {
            self.hasher.update(&*bytes)?;
            Ok(Async::Ready(Some(bytes)))
        } else {
            self.hasher.finish()?;
            Ok(Async::Ready(None))
        }
    }
}

struct SafeHasher {
    max_size: u64,
    min_bytes_per_second: u32,
    hasher: Option<(digest::Context, HashValue)>,
    start_time: Option<DateTime<Utc>>,
    bytes_read: u64,
}

impl SafeHasher {
    fn new(
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
                        )))
                    }
                };
                Some((ctx, value))
            }
            None => None,
        };

        Ok(SafeHasher {
            max_size,
            min_bytes_per_second,
            hasher,
            start_time: None,
            bytes_read: 0,
        })
    }

    fn update(&mut self, buf: &[u8]) -> io::Result<()> {
        if self.start_time.is_none() {
            self.start_time = Some(Utc::now())
        }

        match self.bytes_read.checked_add(buf.len() as u64) {
            Some(sum) if sum <= self.max_size => self.bytes_read = sum,
            _ => {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "Read exceeded the maximum allowed bytes.",
                ));
            }
        }

        let duration = Utc::now().signed_duration_since(self.start_time.unwrap());
        // 30 second grace period before we start checking the bitrate
        if duration.num_seconds() >= 30 {
            if self.bytes_read as f32 / (duration.num_seconds() as f32)
                < self.min_bytes_per_second as f32
            {
                return Err(io::Error::new(
                    ErrorKind::TimedOut,
                    "Read aborted. Bitrate too low.",
                ));
            }
        }

        if let Some((ref mut context, _)) = self.hasher {
            context.update(buf);
        }

        Ok(())
    }

    fn finish(&mut self) -> io::Result<()> {
        if let Some((context, expected_hash)) = self.hasher.take() {
            let generated_hash = context.finish();
            if generated_hash.as_ref() != expected_hash.value() {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "Calculated hash did not match the required hash.",
                ));
            }
        }

        Ok(())
    }
}

/// Helper function to convert an ok type into a future.
pub fn future_ok<T: 'static, E: 'static>(value: T) -> Box<Future<Item=T, Error=E>> {
    Box::new(future::ok(value))
}

/// Helper function to convert a error type into a future.
pub fn future_err<T: 'static, E: 'static>(err: E) -> Box<Future<Item=T, Error=E>> {
    Box::new(future::err(err))
}

/// Helper function to convert an error type into a stream.
pub fn stream_err<T: 'static, E: 'static>(err: E) -> Box<Stream<Item=T, Error=E>> {
    Box::new(stream::once(Err::<T, E>(err)))
}

#[cfg(test)]
mod test {
    use futures::stream;
    use bytes::Bytes;
    use super::*;

    #[test]
    fn valid_read() {
        let bytes: &[u8] = &[0x00, 0x01, 0x02, 0x03];
        let reader = SafeStream::new(
            stream::once(Ok(Bytes::from_static(bytes))),
            bytes.len() as u64,
            0,
            None,
        ).unwrap();
        let buf = reader.concat2().wait().unwrap();
        assert_eq!(buf, bytes);
    }

    #[test]
    fn valid_read_large_data() {
        let bytes: &[u8] = &[0x00; 64 * 1024];
        let reader = SafeStream::new(
            stream::once(Ok(Bytes::from_static(bytes))),
            bytes.len() as u64,
            0,
            None,
        ).unwrap();
        let buf = reader.concat2().wait().unwrap();
        assert_eq!(buf, bytes);
    }

    #[test]
    fn valid_read_below_max_size() {
        let bytes: &[u8] = &[0x00, 0x01, 0x02, 0x03];
        let reader = SafeStream::new(
            stream::once(Ok(Bytes::from_static(bytes))),
            (bytes.len() as u64) + 1,
            0,
            None,
        ).unwrap();
        let buf = reader.concat2().wait().unwrap();
        assert_eq!(buf, bytes);
    }

    #[test]
    fn invalid_read_above_max_size() {
        let bytes: &[u8] = &[0x00, 0x01, 0x02, 0x03];
        let reader = SafeStream::new(
            stream::once(Ok(Bytes::from_static(bytes))),
            (bytes.len() as u64) - 1,
            0,
            None,
        ).unwrap();
        assert!(reader.concat2().wait().is_err());
    }

    #[test]
    fn invalid_read_above_max_size_large_data() {
        let bytes: &[u8] = &[0x00; 64 * 1024];
        let reader = SafeStream::new(
            stream::once(Ok(Bytes::from_static(bytes))),
            (bytes.len() as u64) - 1,
            0,
            None,
        ).unwrap();
        assert!(reader.concat2().wait().is_err());
    }

    #[test]
    fn valid_read_good_hash() {
        let bytes: &[u8] = &[0x00, 0x01, 0x02, 0x03];
        let mut context = digest::Context::new(&SHA256);
        context.update(&bytes);
        let hash_value = HashValue::new(context.finish().as_ref().to_vec());
        let reader = SafeStream::new(
            stream::once(Ok(Bytes::from_static(bytes))),
            bytes.len() as u64,
            0,
            Some((&HashAlgorithm::Sha256, hash_value)),
        ).unwrap();

        let buf = reader.concat2().wait().unwrap();
        assert_eq!(buf, bytes);
    }

    #[test]
    fn invalid_read_bad_hash() {
        let bytes: &[u8] = &[0x00, 0x01, 0x02, 0x03];
        let mut context = digest::Context::new(&SHA256);
        context.update(&bytes);
        context.update(&[0xFF]); // evil bytes
        let hash_value = HashValue::new(context.finish().as_ref().to_vec());
        let reader = SafeStream::new(
            stream::once(Ok(Bytes::from_static(bytes))),
            bytes.len() as u64,
            0,
            Some((&HashAlgorithm::Sha256, hash_value)),
        ).unwrap();
        assert!(reader.concat2().wait().is_err());
    }

    #[test]
    fn valid_read_good_hash_large_data() {
        let bytes: &[u8] = &[0x00; 64 * 1024];
        let mut context = digest::Context::new(&SHA256);
        context.update(&bytes);
        let hash_value = HashValue::new(context.finish().as_ref().to_vec());
        let reader = SafeStream::new(
            stream::once(Ok(Bytes::from_static(bytes))),
            bytes.len() as u64,
            0,
            Some((&HashAlgorithm::Sha256, hash_value)),
        ).unwrap();

        let buf = reader.concat2().wait().unwrap();
        assert_eq!(buf, bytes);
    }

    #[test]
    fn invalid_read_bad_hash_large_data() {
        let bytes: &[u8] = &[0x00; 64 * 1024];
        let mut context = digest::Context::new(&SHA256);
        context.update(&bytes);
        context.update(&[0xFF]); // evil bytes
        let hash_value = HashValue::new(context.finish().as_ref().to_vec());
        let reader = SafeStream::new(
            stream::once(Ok(Bytes::from_static(bytes))),
            bytes.len() as u64,
            0,
            Some((&HashAlgorithm::Sha256, hash_value)),
        ).unwrap();
        assert!(reader.concat2().wait().is_err());
    }
}
