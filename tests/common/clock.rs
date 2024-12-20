use std::time::Duration;

use torrust_tracker_clock::clock::Time;

use crate::CurrentClock;

#[test]
fn it_should_use_stopped_time_for_testing() {
    assert_eq!(CurrentClock::dbg_clock_type(), "Stopped".to_owned());

    let time = CurrentClock::now();
    std::thread::sleep(Duration::from_millis(50));
    let time_2 = CurrentClock::now();

    assert_eq!(time, time_2);
}
