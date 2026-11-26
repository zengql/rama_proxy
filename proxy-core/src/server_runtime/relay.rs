use std::{
    io,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf, copy_bidirectional},
    time::{Instant, sleep_until},
};

pub(super) async fn copy_with_idle_timeout<A, B>(
    stream: &mut A,
    upstream: &mut B,
    idle_timeout: Duration,
) -> io::Result<Option<(u64, u64)>>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let started = Instant::now();
    let last_activity_ms = AtomicU64::new(0);
    let mut tracked = ActivityStream {
        stream,
        started,
        last_activity_ms: &last_activity_ms,
    };
    let wait_for_idle = async {
        let mut last_activity_ms_seen = 0;
        loop {
            sleep_until(started + Duration::from_millis(last_activity_ms_seen) + idle_timeout)
                .await;
            let latest = last_activity_ms.load(Ordering::Relaxed);
            if latest == last_activity_ms_seen {
                break;
            }
            last_activity_ms_seen = latest;
        }
    };

    tokio::select! {
        result = copy_bidirectional(&mut tracked, upstream) => result.map(Some),
        () = wait_for_idle => Ok(None),
    }
}

struct ActivityStream<'a, S> {
    stream: &'a mut S,
    started: Instant,
    last_activity_ms: &'a AtomicU64,
}

impl<S> ActivityStream<'_, S> {
    fn record_activity(&self) {
        self.last_activity_ms
            .store(self.started.elapsed().as_millis() as u64, Ordering::Relaxed);
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ActivityStream<'_, S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut *self.stream).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.record_activity();
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ActivityStream<'_, S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut *self.stream).poll_write(cx, buf);
        if matches!(result, Poll::Ready(Ok(written)) if written > 0) {
            self.record_activity();
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.stream).poll_shutdown(cx)
    }
}
