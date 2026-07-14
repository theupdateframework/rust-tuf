//! Utility functions and adapters for async readers and bitrate enforcement.

use futures_io::AsyncRead;
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

/// Wraps an `AsyncRead` to detect and fail transfers slower than a minimum bitrate.
pub(crate) struct EnforceMinimumBitrate<R> {
    inner: R,
    min_bytes_per_second: u32,
    start_time: Option<Instant>,
    bytes_read: u64,
}

impl<R: AsyncRead> EnforceMinimumBitrate<R> {
    /// Create a new `EnforceMinimumBitrate`.
    pub(crate) fn new(read: R, min_bytes_per_second: u32) -> Self {
        Self {
            inner: read,
            min_bytes_per_second,
            start_time: None,
            bytes_read: 0,
        }
    }
}

#[cfg(not(test))]
const BITRATE_GRACE_PERIOD: Duration = Duration::from_secs(30);
#[cfg(test)]
const BITRATE_GRACE_PERIOD: Duration = Duration::from_secs(1);

impl<R: AsyncRead + Unpin> AsyncRead for EnforceMinimumBitrate<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        // FIXME(#272) transfers that stall out completely won't enforce the minimum bit rate.
        let read_bytes = futures_util::ready!(Pin::new(&mut self.inner).poll_read(cx, buf))?;

        let start_time = *self.start_time.get_or_insert_with(Instant::now);

        if read_bytes == 0 {
            return Poll::Ready(Ok(0));
        }

        self.bytes_read += read_bytes as u64;

        // allow a grace period before we start checking the bitrate
        let duration = start_time.elapsed();
        if duration >= BITRATE_GRACE_PERIOD {
            if (self.bytes_read as f32) / duration.as_secs_f32() < self.min_bytes_per_second as f32
            {
                return Poll::Ready(Err(io::Error::new(
                    ErrorKind::TimedOut,
                    "Read aborted. Bitrate too low.",
                )));
            }
        }

        Poll::Ready(Ok(read_bytes))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use futures_executor::block_on;
    use futures_util::AsyncReadExt;

    #[test]
    fn enforce_minimum_bitrate_is_identity_for_fast_transfers() {
        block_on(async {
            let bytes: &[u8] = &[0x42; 64 * 1024];

            let mut reader = EnforceMinimumBitrate::new(bytes, 100);

            let mut buf = Vec::new();
            assert!(reader.read_to_end(&mut buf).await.is_ok());
            assert_eq!(bytes, &buf[..]);
        })
    }

    #[test]
    fn enforce_minimum_bitrate_is_fails_when_reader_is_too_slow() {
        block_on(async {
            let bytes: &[u8] = &[0x42; 64 * 1024];

            let mut reader = EnforceMinimumBitrate::new(bytes, 100);

            let mut buf = vec![0; 50];

            assert!(reader.read_exact(&mut buf).await.is_ok());
            assert_eq!(buf, &[0x42; 50][..]);

            std::thread::sleep(BITRATE_GRACE_PERIOD);

            assert!(reader.read_to_end(&mut buf).await.is_err());
        })
    }
}
