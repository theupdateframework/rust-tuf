use chrono::offset::Utc;
use chrono::DateTime;
use ring::digest::{self, SHA256, SHA512};
use std::io::{self, Read, ErrorKind};

use crypto::{HashAlgorithm, HashValue};

/// Wraps a `Read` to ensure that the consumer can't read more than a capped maximum number of
/// bytes. Also, this ensures that a minimum bitrate and returns an `Err` if it is not. Finally,
/// when the underlying `Read` is fully consumed, the hash of the data is optional calculated. If
/// the calculated hash does not match the given hash, it will return an `Err`. Consumers of a
/// `SafeReader` should purge and untrust all read bytes if this ever returns an `Err`.
pub struct SafeReader<R: Read> {
    inner: R,
    max_size: u64,
    min_bytes_per_second: u32,
    hasher: Option<(digest::Context, HashValue)>,
    start_time: Option<DateTime<Utc>>,
    bytes_read: u64,
}

impl<R: Read> SafeReader<R> {
    /// Create a new `SafeReader`.
    pub fn new(
        read: R,
        max_size: u64,
        min_bytes_per_second: u32,
        hash_data: Option<(&HashAlgorithm, HashValue)>,
    ) -> Self {
        let hasher = hash_data.map(|(alg, value)| {
            let ctx = match alg {
                &HashAlgorithm::Sha256 => digest::Context::new(&SHA256),
                &HashAlgorithm::Sha512 => digest::Context::new(&SHA512),
            };

            (ctx, value)
        });

        SafeReader {
            inner: read,
            max_size: max_size,
            min_bytes_per_second: min_bytes_per_second,
            hasher: hasher,
            start_time: None,
            bytes_read: 0,
        }
    }
}

impl<R: Read> Read for SafeReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.inner.read(buf) {
            Ok(read_bytes) => {
                if self.start_time.is_none() {
                    self.start_time = Some(Utc::now())
                }

                if read_bytes == 0 {
                    if let Some((context, expected_hash)) = self.hasher.take() {
                        let generated_hash = context.finish();
                        if generated_hash.as_ref() != expected_hash.value() {
                            return Err(io::Error::new(
                                ErrorKind::InvalidData,
                                "Calculated hash did not match the required hash.",
                            ));
                        }
                    }

                    return Ok(0);
                }

                match self.bytes_read.checked_add(read_bytes as u64) {
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
                    if self.bytes_read as f32 / (duration.num_seconds() as f32) <
                        self.min_bytes_per_second as f32
                    {
                        return Err(io::Error::new(
                            ErrorKind::TimedOut,
                            "Read aborted. Bitrate too low.",
                        ));
                    }
                }

                match self.hasher {
                    Some((ref mut context, _)) => context.update(&buf[..(read_bytes)]),
                    None => (),
                }

                Ok(read_bytes)
            }
            e @ Err(_) => e,
        }
    }
}
