use torrust_tracker_lib::servers::udp::server::states::Running;

pub mod asserts;
pub mod contract;
pub mod environment;

pub type Started = environment::Environment<Running>;
