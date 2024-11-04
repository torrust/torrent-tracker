use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Status {
    pub code: String,
    pub message: String,
}
#[derive(Serialize, Deserialize)]
pub struct CheckerOutput {
    pub url: String,
    pub status: Status,
}
