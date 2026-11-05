//! Auto-reconnect delays.

use std::time::Duration;

/// 2 / 5 / 10 / 30 s, then 30 s.
pub const DEFAULT_BACKOFF: [Duration; 4] = [
    Duration::from_secs(2),
    Duration::from_secs(5),
    Duration::from_secs(10),
    Duration::from_secs(30),
];

/// Delay before reconnect attempt number `attempt` (0-based); the last entry repeats.
///
/// # Panics
/// When `schedule` is empty.
pub fn backoff_delay(attempt: u32, schedule: &[Duration]) -> Duration {
    assert!(!schedule.is_empty(), "Backoff schedule must not be empty");
    let i = usize::try_from(attempt)
        .unwrap_or(usize::MAX)
        .min(schedule.len() - 1);
    schedule[i]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn follows_the_schedule_and_stays_at_the_last_step() {
        let got: Vec<u64> = (0..7)
            .map(|i| backoff_delay(i, &DEFAULT_BACKOFF).as_secs())
            .collect();
        assert_eq!(got, [2, 5, 10, 30, 30, 30, 30]);
    }

    #[test]
    #[should_panic(expected = "must not be empty")]
    fn rejects_an_empty_schedule() {
        let _ = backoff_delay(0, &[]);
    }
}
