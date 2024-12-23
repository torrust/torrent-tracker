use std::fmt;
use std::time::Duration;

use tower_http::LatencyUnit;

/// This is the prefix used in logs to identify a started service.
///
/// For example:
///
/// ```text
/// 2024-06-25T12:36:25.025312Z  INFO UDP TRACKER: Started on: udp://0.0.0.0:6969
/// 2024-06-25T12:36:25.025445Z  INFO HTTP TRACKER: Started on: http://0.0.0.0:7070
/// 2024-06-25T12:36:25.025527Z  INFO API: Started on http://0.0.0.0:1212
/// 2024-06-25T12:36:25.025580Z  INFO HEALTH CHECK API: Started on: http://127.0.0.1:1313
/// ```
pub const STARTED_ON: &str = "Started on";

/*

todo: we should use a field fot the URL.

For example, instead of:

```
2024-06-25T12:36:25.025312Z  INFO UDP TRACKER: Started on: udp://0.0.0.0:6969
```

We should use something like:

```
2024-06-25T12:36:25.025312Z  INFO UDP TRACKER started_at_url=udp://0.0.0.0:6969
```

*/

pub struct Latency {
    unit: LatencyUnit,
    duration: Duration,
}

impl Latency {
    #[must_use]
    pub fn new(unit: LatencyUnit, duration: Duration) -> Self {
        Self { unit, duration }
    }
}

impl fmt::Display for Latency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.unit {
            LatencyUnit::Seconds => write!(f, "{} s", self.duration.as_secs_f64()),
            LatencyUnit::Millis => write!(f, "{} ms", self.duration.as_millis()),
            LatencyUnit::Micros => write!(f, "{} μs", self.duration.as_micros()),
            LatencyUnit::Nanos => write!(f, "{} ns", self.duration.as_nanos()),
            _ => panic!("Invalid latency unit"),
        }
    }
}
