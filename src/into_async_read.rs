// FIXME: remove once https://github.com/rust-lang-nursery/futures-rs/pull/1367 lands in a release.

use futures::io::AsyncRead;
use futures::ready;
use futures::stream::TryStream;
use futures::task::{LocalWaker, Poll};
use std::cmp;
use std::io::{Error, Result};
use std::marker::Unpin;
use std::pin::Pin;

pub struct IntoAsyncRead<St>
where
    St: TryStream<Error = Error> + Unpin,
    St::Ok: AsRef<[u8]>,
{
    stream: St,
    state: ReadState<St::Ok>,
}

impl<St> Unpin for IntoAsyncRead<St>
where
    St: TryStream<Error = Error> + Unpin,
    St::Ok: AsRef<[u8]>,
{
}

#[derive(Debug)]
enum ReadState<T: AsRef<[u8]>> {
    Ready { chunk: T, chunk_start: usize },
    PendingChunk,
    Eof,
}

impl<St> IntoAsyncRead<St>
where
    St: TryStream<Error = Error> + Unpin,
    St::Ok: AsRef<[u8]>,
{
    pub(super) fn new(stream: St) -> Self {
        IntoAsyncRead {
            stream,
            state: ReadState::PendingChunk,
        }
    }
}

impl<St> AsyncRead for IntoAsyncRead<St>
where
    St: TryStream<Error = Error> + Unpin,
    St::Ok: AsRef<[u8]>,
{
    fn poll_read(&mut self, lw: &LocalWaker, buf: &mut [u8]) -> Poll<Result<usize>> {
        loop {
            match &mut self.state {
                ReadState::Ready { chunk, chunk_start } => {
                    let chunk = chunk.as_ref();
                    let len = cmp::min(buf.len(), chunk.len() - *chunk_start);

                    buf[..len].copy_from_slice(&chunk[*chunk_start..*chunk_start + len]);
                    *chunk_start += len;

                    if chunk.len() == *chunk_start {
                        self.state = ReadState::PendingChunk;
                    }

                    return Poll::Ready(Ok(len));
                }
                ReadState::PendingChunk => {
                    match ready!(Pin::new(&mut self.stream).try_poll_next(lw)) {
                        Some(Ok(chunk)) => {
                            self.state = ReadState::Ready {
                                chunk,
                                chunk_start: 0,
                            };
                            continue;
                        }
                        Some(Err(err)) => {
                            return Poll::Ready(Err(err));
                        }
                        None => {
                            self.state = ReadState::Eof;
                            return Poll::Ready(Ok(0));
                        }
                    }
                }
                ReadState::Eof => {
                    return Poll::Ready(Ok(0));
                }
            }
        }
    }
}
