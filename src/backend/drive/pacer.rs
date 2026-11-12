//! AIMD pacer and quota-unit window (SPEC §6.5) — owned by WP3.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;

use crate::consts;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CallKind {
    List,
    Get,
    About,
    GenerateIds,
    Download,
    Create,
    CreateFolder,
    Trash,
    Delete,
    UploadPart,
    StatusQuery,
}

impl CallKind {
    pub fn units(self) -> u32 {
        match self {
            CallKind::List => consts::UNITS_LIST,
            CallKind::Download => consts::UNITS_DOWNLOAD,
            CallKind::Create | CallKind::CreateFolder | CallKind::Trash | CallKind::Delete => {
                consts::UNITS_WRITE
            }
            CallKind::Get | CallKind::About | CallKind::GenerateIds => consts::UNITS_GET,
            CallKind::UploadPart | CallKind::StatusQuery => consts::UNITS_UPLOAD_PART,
        }
    }

    /// `None` = unpaced.
    pub fn class(self) -> Option<Class> {
        match self {
            CallKind::Create | CallKind::CreateFolder | CallKind::Trash | CallKind::Delete => {
                Some(Class::Write)
            }
            CallKind::List
            | CallKind::Get
            | CallKind::About
            | CallKind::GenerateIds
            | CallKind::Download => Some(Class::Read),
            CallKind::UploadPart | CallKind::StatusQuery => None,
        }
    }

    /// The class whose rate a throttling answer lowers. Part PUTs and status queries are not
    /// paced, but they are writes: their throttles and successes count for the write breaker.
    pub(crate) fn throttle_class(self) -> Class {
        self.class().unwrap_or(Class::Write)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Class {
    Write,
    Read,
}

#[derive(Clone, Debug)]
pub struct PacerConfig {
    pub write_start: f64,
    pub write_min: f64,
    pub write_max: f64,
    pub read_start: f64,
    pub read_min: f64,
    pub read_max: f64,
    pub increase_per_10s: f64,
    pub units_per_min: u32,
    pub max_attempts: u32,
    pub breaker: std::time::Duration,
}

impl Default for PacerConfig {
    /// §6.1.
    fn default() -> Self {
        PacerConfig {
            write_start: consts::PACER_WRITE_START,
            write_min: consts::PACER_WRITE_MIN,
            write_max: consts::PACER_WRITE_MAX,
            read_start: consts::PACER_READ_START,
            read_min: consts::PACER_READ_MIN,
            read_max: consts::PACER_READ_MAX,
            increase_per_10s: consts::PACER_INCREASE,
            units_per_min: consts::UNITS_PER_MIN_CAP,
            max_attempts: consts::PACER_MAX_ATTEMPTS,
            breaker: consts::WRITE_BREAKER,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PacerStats {
    pub write_rate: f64,
    pub read_rate: f64,
    pub units_last_min: u32,
    pub throttles: u64,
}

const WINDOW: Duration = Duration::from_secs(60);

/// One AIMD bucket of capacity 1: requests are spaced `1 / rate` apart.
struct Bucket {
    rate: f64,
    min: f64,
    max: f64,
    /// Earliest start of the next request.
    next_slot: Instant,
    /// Last throttle or last additive increase: the increase clock.
    adjusted: Instant,
    /// First and latest throttle of the current run of throttles without one success.
    throttle_run: Option<(Instant, Instant)>,
}

impl Bucket {
    fn new(start: f64, min: f64, max: f64, now: Instant) -> Self {
        // A configuration with min > max or a zero rate must not divide by zero or panic.
        let min = min.max(0.001);
        let max = max.max(min);
        Bucket {
            rate: start.clamp(min, max),
            min,
            max,
            next_slot: now,
            adjusted: now,
            throttle_run: None,
        }
    }

    /// `+increase` per full [`consts::PACER_INCREASE_EVERY`] without throttling.
    fn recover(&mut self, increase: f64, now: Instant) {
        let every = consts::PACER_INCREASE_EVERY;
        let steps = (now.saturating_duration_since(self.adjusted).as_secs_f64()
            / every.as_secs_f64())
        .floor();
        if steps >= 1.0 {
            self.rate = (self.rate + increase * steps).min(self.max);
            self.adjusted += every.mul_f64(steps);
        }
    }
}

struct State {
    write: Bucket,
    read: Bucket,
    /// Quota units spent in the last minute, oldest first.
    window: VecDeque<(Instant, u32)>,
    window_units: u64,
    throttles: u64,
    backoff_unit: Duration,
}

impl State {
    fn bucket(&mut self, class: Class) -> &mut Bucket {
        match class {
            Class::Write => &mut self.write,
            Class::Read => &mut self.read,
        }
    }

    fn prune(&mut self, now: Instant) {
        while let Some(&(at, units)) = self.window.front() {
            if now.saturating_duration_since(at) < WINDOW {
                break;
            }
            self.window.pop_front();
            self.window_units -= u64::from(units);
        }
    }
}

/// Uses `tokio::time` so tests can pause/advance.
pub struct Pacer {
    cfg: PacerConfig,
    state: Mutex<State>,
}

impl Pacer {
    pub fn new(cfg: PacerConfig) -> Self {
        let now = Instant::now();
        let state = State {
            write: Bucket::new(cfg.write_start, cfg.write_min, cfg.write_max, now),
            read: Bucket::new(cfg.read_start, cfg.read_min, cfg.read_max, now),
            window: VecDeque::new(),
            window_units: 0,
            throttles: 0,
            backoff_unit: Duration::from_secs(1),
        };
        Pacer {
            cfg,
            state: Mutex::new(state),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        // Every update leaves the state consistent, so a poisoned lock is still usable.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Token bucket + unit window.
    pub async fn acquire(&self, kind: CallKind) {
        let Some(class) = kind.class() else {
            return;
        };
        let units = kind.units();
        let cap = u64::from(self.cfg.units_per_min);
        loop {
            // The lock is never held across an await.
            let (until, granted) = {
                let mut st = self.lock();
                let now = Instant::now();
                st.prune(now);
                let oldest = st.window.front().map(|&(at, _)| at);
                match oldest {
                    // The window is full: wait until its oldest entry is a minute old. (A single
                    // call larger than the cap passes alone, or it could never pass.)
                    Some(at) if st.window_units + u64::from(units) > cap => (at + WINDOW, false),
                    _ => {
                        let increase = self.cfg.increase_per_10s;
                        let bucket = st.bucket(class);
                        bucket.recover(increase, now);
                        let slot = bucket.next_slot.max(now);
                        bucket.next_slot = slot + Duration::from_secs_f64(1.0 / bucket.rate);
                        if units > 0 {
                            st.window.push_back((now, units));
                            st.window_units += u64::from(units);
                        }
                        (slot, true)
                    }
                }
            };
            tokio::time::sleep_until(until).await;
            if granted {
                return;
            }
        }
    }

    pub fn on_success(&self, kind: CallKind) {
        self.lock().bucket(kind.throttle_class()).throttle_run = None;
    }

    /// Halves the rate; returns the sleep.
    pub fn on_throttle(
        &self,
        kind: CallKind,
        retry_after: Option<std::time::Duration>,
        attempt: u32,
    ) -> std::time::Duration {
        let now = Instant::now();
        let mut st = self.lock();
        st.throttles += 1;
        let unit = st.backoff_unit;
        let breaker = self.cfg.breaker;
        let bucket = st.bucket(kind.throttle_class());
        bucket.rate = (bucket.rate * consts::PACER_DECREASE).max(bucket.min);
        bucket.adjusted = now;
        bucket.throttle_run = match bucket.throttle_run {
            // Throttles that far apart are not one continuous run: nothing was tried between.
            Some((first, latest)) if now.saturating_duration_since(latest) < breaker => {
                Some((first, now))
            }
            _ => Some((now, now)),
        };
        backoff_scaled(unit, attempt).max(retry_after.unwrap_or_default())
    }

    /// `min(2^n s + jitter, 64 s)`.
    pub fn backoff(attempt: u32) -> std::time::Duration {
        backoff_scaled(Duration::from_secs(1), attempt)
    }

    /// [`Pacer::backoff`] in this pacer's time unit (one second unless a test shortened it).
    pub(crate) fn backoff_for(&self, attempt: u32) -> Duration {
        backoff_scaled(self.lock().backoff_unit, attempt)
    }

    /// Test hook: scales every backoff sleep of the backend that owns this pacer (`unit` stands
    /// for the formula's second), so fault-injection tests need not wait real seconds.
    #[doc(hidden)]
    pub fn set_backoff_unit(&self, unit: std::time::Duration) {
        self.lock().backoff_unit = unit;
    }

    pub(crate) fn max_attempts(&self) -> u32 {
        self.cfg.max_attempts.max(1)
    }

    /// Writes were throttled, without one success, over at least the breaker time.
    pub fn write_breaker_tripped(&self) -> bool {
        let run = self.lock().write.throttle_run;
        run.is_some_and(|(first, latest)| {
            latest.saturating_duration_since(first) >= self.cfg.breaker
        })
    }

    pub fn stats(&self) -> PacerStats {
        let now = Instant::now();
        let mut st = self.lock();
        st.prune(now);
        st.write.recover(self.cfg.increase_per_10s, now);
        st.read.recover(self.cfg.increase_per_10s, now);
        PacerStats {
            write_rate: st.write.rate,
            read_rate: st.read.rate,
            units_last_min: u32::try_from(st.window_units).unwrap_or(u32::MAX),
            throttles: st.throttles,
        }
    }
}

/// `min(2^n · unit + rand(0..unit), 64 · unit)`.
fn backoff_scaled(unit: Duration, attempt: u32) -> Duration {
    let cap = unit.saturating_mul(consts::PACER_BACKOFF_MAX.as_secs() as u32);
    let base = unit.saturating_mul(1u32.checked_shl(attempt).unwrap_or(u32::MAX));
    let jitter_ms =
        u64::from_le_bytes(crate::util::random::<8>()) % consts::PACER_BACKOFF_JITTER_MS;
    let jitter = unit.mul_f64(jitter_ms as f64 / consts::PACER_BACKOFF_JITTER_MS as f64);
    base.saturating_add(jitter).min(cap)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPS: f64 = 1e-9;

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    /// Paused-clock timers fire on the next millisecond tick, so a wait may overshoot slightly.
    fn near(got: Duration, want: Duration) -> bool {
        got >= want && got < want + Duration::from_millis(5)
    }

    #[test]
    fn units_and_classes() {
        use CallKind::*;
        assert_eq!(List.units(), 100);
        assert_eq!(Download.units(), 200);
        for k in [Create, CreateFolder, Trash, Delete] {
            assert_eq!((k.units(), k.class()), (50, Some(Class::Write)));
        }
        for k in [Get, About, GenerateIds] {
            assert_eq!((k.units(), k.class()), (5, Some(Class::Read)));
        }
        assert_eq!(List.class(), Some(Class::Read));
        assert_eq!(Download.class(), Some(Class::Read));
        for k in [UploadPart, StatusQuery] {
            assert_eq!((k.units(), k.class()), (0, None));
        }
    }

    #[test]
    fn backoff_formula() {
        for n in 0..6u32 {
            for _ in 0..50 {
                let d = Pacer::backoff(n);
                assert!(
                    d >= secs(1 << n) && d < secs((1 << n) + 1),
                    "backoff({n}) = {d:?}"
                );
            }
        }
        for n in [6, 7, 20, 31, 32, 1000] {
            assert_eq!(Pacer::backoff(n), secs(64), "backoff({n})");
        }
        let d = backoff_scaled(Duration::from_millis(10), 3);
        assert!(d >= Duration::from_millis(80) && d < Duration::from_millis(90));
        assert_eq!(
            backoff_scaled(Duration::from_millis(10), 9),
            Duration::from_millis(640)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn spacing_follows_the_rate() {
        let p = Pacer::new(PacerConfig::default());
        let t0 = Instant::now();
        for _ in 0..9 {
            p.acquire(CallKind::Create).await; // 4/s: slots at 0, 0.25, …, 2.0 s
        }
        assert!(near(t0.elapsed(), secs(2)), "{:?}", t0.elapsed());
        // the classes do not share a bucket
        let t1 = Instant::now();
        p.acquire(CallKind::Get).await;
        assert_eq!(t1.elapsed(), Duration::ZERO);
        // unpaced kinds never wait and cost nothing
        for _ in 0..1000 {
            p.acquire(CallKind::UploadPart).await;
            p.acquire(CallKind::StatusQuery).await;
        }
        assert_eq!(t1.elapsed(), Duration::ZERO);
        assert_eq!(p.stats().units_last_min, 9 * 50 + 5);
    }

    #[tokio::test(start_paused = true)]
    async fn halves_on_throttle_and_recovers() {
        let p = Pacer::new(PacerConfig::default());
        assert!((p.stats().write_rate - 4.0).abs() < EPS);
        p.on_throttle(CallKind::Create, None, 0);
        assert!((p.stats().write_rate - 2.0).abs() < EPS);
        assert!(
            (p.stats().read_rate - 10.0).abs() < EPS,
            "the read class is untouched"
        );
        p.on_throttle(CallKind::Trash, None, 1);
        p.on_throttle(CallKind::Delete, None, 2);
        assert!((p.stats().write_rate - 0.5).abs() < EPS);
        p.on_throttle(CallKind::CreateFolder, None, 3);
        assert!(
            (p.stats().write_rate - 0.5).abs() < EPS,
            "never below the minimum"
        );
        assert_eq!(p.stats().throttles, 4);

        // +0.5/s per full 10 s without throttling
        tokio::time::advance(Duration::from_millis(9_999)).await;
        assert!((p.stats().write_rate - 0.5).abs() < EPS);
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!((p.stats().write_rate - 1.0).abs() < EPS);
        tokio::time::advance(secs(25)).await;
        assert!((p.stats().write_rate - 2.0).abs() < EPS);
        // a throttle restarts the 10 s clock
        p.on_throttle(CallKind::Create, None, 0);
        assert!((p.stats().write_rate - 1.0).abs() < EPS);
        tokio::time::advance(secs(9)).await;
        assert!((p.stats().write_rate - 1.0).abs() < EPS);
        tokio::time::advance(secs(1)).await;
        assert!((p.stats().write_rate - 1.5).abs() < EPS);
        // … up to the maximum, not beyond
        tokio::time::advance(secs(3600)).await;
        assert!((p.stats().write_rate - 20.0).abs() < EPS);

        // the halved rate is what acquire() spaces by
        let p = Pacer::new(PacerConfig::default());
        p.on_throttle(CallKind::Get, None, 0); // read: 10/s → 5/s
        let t0 = Instant::now();
        for _ in 0..6 {
            p.acquire(CallKind::Get).await;
        }
        assert!(near(t0.elapsed(), secs(1)), "{:?}", t0.elapsed());
        // an upload part that is throttled slows the write class
        p.on_throttle(CallKind::UploadPart, None, 0);
        assert!((p.stats().write_rate - 2.0).abs() < EPS);
    }

    #[tokio::test(start_paused = true)]
    async fn retry_after_is_honoured() {
        let p = Pacer::new(PacerConfig::default());
        // BACKOFF(0) is 1..2 s: a longer Retry-After wins, a shorter one does not
        assert_eq!(p.on_throttle(CallKind::List, Some(secs(30)), 0), secs(30));
        let d = p.on_throttle(CallKind::List, Some(Duration::from_millis(10)), 0);
        assert!(d >= secs(1) && d < secs(2));
        let d = p.on_throttle(CallKind::List, None, 3);
        assert!(d >= secs(8) && d < secs(9));
        assert_eq!(p.on_throttle(CallKind::List, Some(secs(500)), 9), secs(500));
    }

    #[tokio::test(start_paused = true)]
    async fn unit_window_blocks_at_the_cap() {
        let cfg = PacerConfig {
            read_start: 1000.0,
            read_max: 1000.0,
            ..PacerConfig::default()
        };
        let p = Pacer::new(cfg);
        let t0 = Instant::now();
        // 250,000 units = 1250 downloads of 200 units; at 1000/s they take 1.249 s
        for _ in 0..1250 {
            p.acquire(CallKind::Download).await;
        }
        assert!(t0.elapsed() < secs(2));
        assert_eq!(p.stats().units_last_min, 250_000);
        // the window is full: the next call waits until the oldest entry is a minute old
        p.acquire(CallKind::Get).await;
        assert!(near(t0.elapsed(), secs(60)), "{:?}", t0.elapsed());
        assert!(p.stats().units_last_min <= 250_000);
        // listings are held back by the same window
        let t1 = Instant::now();
        for _ in 0..100 {
            p.acquire(CallKind::List).await;
        }
        assert!(p.stats().units_last_min <= 250_000);
        assert!(t1.elapsed() > Duration::ZERO);
        // after a quiet minute the window is empty again
        tokio::time::advance(secs(61)).await;
        assert_eq!(p.stats().units_last_min, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn write_breaker() {
        let p = Pacer::new(PacerConfig::default());
        assert!(!p.write_breaker_tripped());
        p.on_throttle(CallKind::Create, None, 0);
        tokio::time::advance(secs(300)).await;
        p.on_throttle(CallKind::Trash, None, 3);
        tokio::time::advance(secs(299)).await;
        p.on_throttle(CallKind::Create, None, 5);
        assert!(!p.write_breaker_tripped(), "599 s of throttling");
        tokio::time::advance(secs(1)).await;
        assert!(!p.write_breaker_tripped(), "time alone does not trip it");
        p.on_throttle(CallKind::Create, None, 6);
        assert!(p.write_breaker_tripped(), "10 min of throttled writes");

        // one success ends the run
        p.on_success(CallKind::Create);
        assert!(!p.write_breaker_tripped());
        p.on_throttle(CallKind::Create, None, 0);
        tokio::time::advance(secs(400)).await;
        p.on_throttle(CallKind::Create, None, 0);
        p.on_success(CallKind::UploadPart); // a part that got through is a write that worked
        p.on_throttle(CallKind::UploadPart, None, 0);
        tokio::time::advance(secs(400)).await;
        p.on_throttle(CallKind::UploadPart, None, 0);
        assert!(!p.write_breaker_tripped());
        tokio::time::advance(secs(200)).await;
        p.on_throttle(CallKind::StatusQuery, None, 0);
        assert!(
            p.write_breaker_tripped(),
            "throttled parts are throttled writes"
        );

        // read throttling and read successes do not touch the write breaker
        let p = Pacer::new(PacerConfig::default());
        p.on_throttle(CallKind::List, None, 0);
        tokio::time::advance(secs(500)).await;
        p.on_throttle(CallKind::List, None, 0);
        tokio::time::advance(secs(500)).await;
        p.on_throttle(CallKind::List, None, 0);
        assert!(!p.write_breaker_tripped());
        p.on_throttle(CallKind::Create, None, 0);
        tokio::time::advance(secs(599)).await;
        p.on_throttle(CallKind::Create, None, 0);
        tokio::time::advance(secs(1)).await;
        p.on_success(CallKind::List);
        p.on_throttle(CallKind::Create, None, 0);
        assert!(p.write_breaker_tripped());

        // two throttles with a long quiet time between them are not continuous throttling
        let p = Pacer::new(PacerConfig::default());
        p.on_throttle(CallKind::Create, None, 0);
        tokio::time::advance(secs(700)).await;
        p.on_throttle(CallKind::Create, None, 0);
        assert!(!p.write_breaker_tripped());
        tokio::time::advance(secs(599)).await;
        p.on_throttle(CallKind::Create, None, 0);
        assert!(!p.write_breaker_tripped());
        tokio::time::advance(secs(1)).await;
        p.on_throttle(CallKind::Create, None, 0);
        assert!(p.write_breaker_tripped());
    }

    #[tokio::test(start_paused = true)]
    async fn backoff_unit_scales_the_sleeps() {
        let p = Pacer::new(PacerConfig::default());
        p.set_backoff_unit(Duration::from_millis(4));
        let d = p.backoff_for(2);
        assert!(d >= Duration::from_millis(16) && d < Duration::from_millis(20));
        let d = p.on_throttle(CallKind::Create, None, 0);
        assert!(d >= Duration::from_millis(4) && d < Duration::from_millis(8));
        assert_eq!(p.on_throttle(CallKind::Create, Some(secs(1)), 0), secs(1));
    }
}
