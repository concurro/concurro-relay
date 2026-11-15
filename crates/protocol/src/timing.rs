//! Named wall-clock phases of one exchange.

use std::time::Instant;

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Laps {
    #[serde(skip)]
    last: Instant,
    laps: Vec<(&'static str, f64)>,
}

impl Laps {
    pub fn start() -> Self {
        Self { last: Instant::now(), laps: Vec::new() }
    }

    /// Closes the phase running since the previous lap, in seconds.
    pub fn lap(&mut self, name: &'static str) {
        let now = Instant::now();
        self.laps.push((name, (now - self.last).as_secs_f64()));
        self.last = now;
    }

    pub fn iter(&self) -> impl Iterator<Item = (&'static str, f64)> + '_ {
        self.laps.iter().copied()
    }
}
