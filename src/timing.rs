use std::time::Duration;

use rand::Rng;

/// Timing jitter options.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TimingJitter {
    pub min_ms: u64,
    pub max_ms: u64,
}

impl TimingJitter {
    #[must_use]
    pub fn new(min_ms: u64, max_ms: u64) -> Self {
        Self { min_ms, max_ms }
    }

    #[must_use]
    pub fn sample_delay(&self, rng: &mut impl Rng) -> Duration {
        if self.max_ms <= self.min_ms {
            return Duration::from_millis(self.min_ms);
        }
        Duration::from_millis(rng.gen_range(self.min_ms..=self.max_ms))
    }

    #[must_use]
    pub fn burstiness(&self) -> bool {
        self.max_ms.saturating_sub(self.min_ms) % 2 == 0
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TimingJitterConfig {
    pub min_ms: u64,
    pub max_ms: u64,
}

impl Default for TimingJitterConfig {
    fn default() -> Self {
        Self {
            min_ms: 80,
            max_ms: 350,
        }
    }
}

impl From<TimingJitterConfig> for TimingJitter {
    fn from(value: TimingJitterConfig) -> Self {
        Self::new(value.min_ms, value.max_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn delay_is_within_bounds() {
        let jitter = TimingJitter::new(10, 20);
        let mut rng = StdRng::seed_from_u64(7);
        for _ in 0..20 {
            let d = jitter.sample_delay(&mut rng);
            assert!(d.as_millis() >= 10 && d.as_millis() <= 20);
        }
    }

    #[test]
    fn zero_range_is_stable() {
        let jitter = TimingJitter::new(12, 12);
        let mut rng = StdRng::seed_from_u64(7);
        assert_eq!(jitter.sample_delay(&mut rng), Duration::from_millis(12));
    }
}
