/// Temporary handler for testing and debugging the new Axum implementation
/// It should be removed once the migration to Axum is finished.
use axum::response::Json;

use crate::http::axum_implementation::resources::ok::Ok;
use crate::http::axum_implementation::responses::ok;

#[allow(clippy::unused_async)]
pub async fn get_status_handler() -> Json<Ok> {
    ok::response()
}
