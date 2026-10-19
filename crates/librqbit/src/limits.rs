use arc_swap::ArcSwapOption;
use governor::DefaultDirectRateLimiter as RateLimiter;
use governor::Quota;
use librqbit_core::constants::CHUNK_SIZE;
use serde::Deserialize;
use serde::Serialize;
use std::num::NonZeroU32;
use std::sync::Arc;

#[derive(Default, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct LimitsConfig {
    pub upload_bps: Option<NonZeroU32>,
    pub download_bps: Option<NonZeroU32>,
}

struct Limit {
    // Loaded afresh by every acquire, so a rate set while acquires run applies
    // from the next one on.
    limiter: ArcSwapOption<RateLimiter>,
    current_bps: std::sync::atomic::AtomicU32,
    // Bytes this limit has let through.
    granted: tokio::sync::watch::Sender<u64>,
}

impl Limit {
    // The burst holds at least one full request (a request never exceeds
    // CHUNK_SIZE), so a rate below that makes an acquire wait, never fail.
    fn new_inner(bps: Option<NonZeroU32>) -> Option<Arc<RateLimiter>> {
        let bps = bps?;
        let burst = bps.max(NonZeroU32::new(CHUNK_SIZE).expect("CHUNK_SIZE is not zero"));
        Some(Arc::new(RateLimiter::direct(
            Quota::per_second(bps).allow_burst(burst),
        )))
    }

    fn new(bps: Option<NonZeroU32>) -> Self {
        use std::sync::atomic::AtomicU32;
        Self {
            limiter: ArcSwapOption::new(Self::new_inner(bps)),
            current_bps: AtomicU32::new(bps.map(|v| v.get()).unwrap_or(0)),
            granted: tokio::sync::watch::Sender::new(0),
        }
    }

    async fn acquire(&self, size: NonZeroU32) -> crate::Result<()> {
        let lim = self.limiter.load().clone();
        if let Some(rl) = lim.as_ref() {
            rl.until_n_ready(size).await?;
        }
        self.granted.send_modify(|g| *g += u64::from(size.get()));
        Ok(())
    }

    fn set(&self, limit: Option<NonZeroU32>) {
        use std::sync::atomic::Ordering;
        let new = Self::new_inner(limit);
        self.limiter.swap(new);
        self.current_bps
            .store(limit.map(|v| v.get()).unwrap_or(0), Ordering::Relaxed);
    }

    fn get(&self) -> Option<NonZeroU32> {
        use std::sync::atomic::Ordering;
        NonZeroU32::new(self.current_bps.load(Ordering::Relaxed))
    }
}

pub struct Limits {
    down: Limit,
    up: Limit,
}

impl Default for Limits {
    fn default() -> Self {
        Self::new(LimitsConfig::default())
    }
}

impl Limits {
    pub fn new(config: LimitsConfig) -> Self {
        Self {
            down: Limit::new(config.download_bps),
            up: Limit::new(config.upload_bps),
        }
    }

    pub async fn prepare_for_upload(&self, len: NonZeroU32) -> crate::Result<()> {
        self.up.acquire(len).await
    }

    pub async fn prepare_for_download(&self, len: NonZeroU32) -> crate::Result<()> {
        self.down.acquire(len).await
    }

    pub fn set_upload_bps(&self, bps: Option<NonZeroU32>) {
        self.up.set(bps);
    }

    pub fn set_download_bps(&self, bps: Option<NonZeroU32>) {
        self.down.set(bps);
    }

    pub fn get_upload_bps(&self) -> Option<NonZeroU32> {
        self.up.get()
    }

    pub fn get_download_bps(&self) -> Option<NonZeroU32> {
        self.down.get()
    }

    pub fn get_config(&self) -> LimitsConfig {
        LimitsConfig {
            upload_bps: self.get_upload_bps(),
            download_bps: self.get_download_bps(),
        }
    }

    /// Set both rates. Acquires already waiting finish against the old rate;
    /// every later one uses the new one.
    pub fn set_config(&self, config: LimitsConfig) {
        self.set_upload_bps(config.upload_bps);
        self.set_download_bps(config.download_bps);
    }

    /// Bytes let through for download so far; the receiver sees every later grant.
    pub fn watch_download_granted(&self) -> tokio::sync::watch::Receiver<u64> {
        self.down.granted.subscribe()
    }

    /// Bytes let through for upload so far; the receiver sees every later grant.
    pub fn watch_upload_granted(&self) -> tokio::sync::watch::Receiver<u64> {
        self.up.granted.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use futures::FutureExt;
    use librqbit_core::constants::CHUNK_SIZE;

    use super::{Limits, LimitsConfig};

    fn bps(v: u32) -> Option<NonZeroU32> {
        NonZeroU32::new(v)
    }

    // Each limiter starts with a full burst of max(rate, CHUNK_SIZE). Whether an
    // acquire is granted on its first poll or left waiting shows which rate it
    // met, with no dependence on the clock beyond a refill of at most a few
    // bytes between two adjacent polls.
    #[test]
    fn test_a_rate_change_applies_to_the_next_acquire() {
        let limits = Limits::new(LimitsConfig {
            upload_bps: None,
            download_bps: bps(1024),
        });
        let chunk = NonZeroU32::new(CHUNK_SIZE).unwrap();
        let granted = limits.watch_download_granted();

        // The first full request drains the burst; the next one has to wait for a
        // refill at 1024 B/s.
        assert!(matches!(
            limits.prepare_for_download(chunk).now_or_never(),
            Some(Ok(()))
        ));
        assert!(limits.prepare_for_download(chunk).now_or_never().is_none());
        assert_eq!(*granted.borrow(), u64::from(CHUNK_SIZE));

        // A higher rate is a new limiter with a full burst: the next acquire is
        // granted at once.
        let four = NonZeroU32::new(4 * CHUNK_SIZE).unwrap();
        limits.set_config(LimitsConfig {
            upload_bps: bps(512),
            download_bps: bps(4 * CHUNK_SIZE),
        });
        assert_eq!(
            limits.get_config(),
            LimitsConfig {
                upload_bps: bps(512),
                download_bps: bps(4 * CHUNK_SIZE),
            }
        );
        assert!(matches!(
            limits.prepare_for_download(four).now_or_never(),
            Some(Ok(()))
        ));
        assert_eq!(*granted.borrow(), 5 * u64::from(CHUNK_SIZE));

        // None is unlimited.
        limits.set_config(LimitsConfig::default());
        let big = NonZeroU32::new(u32::MAX).unwrap();
        assert!(matches!(
            limits.prepare_for_upload(big).now_or_never(),
            Some(Ok(()))
        ));
        assert!(matches!(
            limits.prepare_for_download(big).now_or_never(),
            Some(Ok(()))
        ));
        assert_eq!(limits.get_config(), LimitsConfig::default());
    }

    // A cap below one request's size admits a full request: it waits for the
    // refill instead of failing with insufficient capacity.
    #[test]
    fn test_a_cap_below_one_request_waits_instead_of_failing() {
        let limits = Limits::new(LimitsConfig {
            upload_bps: bps(1024),
            download_bps: bps(1024),
        });
        let chunk = NonZeroU32::new(CHUNK_SIZE).unwrap();
        for _ in 0..2 {
            assert!(matches!(
                limits.prepare_for_upload(chunk).now_or_never(),
                Some(Ok(()))
            ));
            assert!(matches!(
                limits.prepare_for_download(chunk).now_or_never(),
                Some(Ok(()))
            ));
            // The burst is spent: the next full request is pending, not an error.
            assert!(limits.prepare_for_upload(chunk).now_or_never().is_none());
            assert!(limits.prepare_for_download(chunk).now_or_never().is_none());
            // Independent of the clock: the quota has capacity for a full request
            // (Ok, whether ready now or later), never InsufficientCapacity.
            for limit in [&limits.up, &limits.down] {
                let rl = limit.limiter.load_full().expect("capped");
                assert!(rl.check_n(chunk).is_ok(), "insufficient capacity");
            }
            // A rate change refills the burst.
            limits.set_config(LimitsConfig {
                upload_bps: bps(1024),
                download_bps: bps(1024),
            });
        }
    }
}
