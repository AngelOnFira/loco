//! # Test Utilities Module
//!
//! This module provides utility functions and constants for easy testing
//! purposes, including cleaning up data patterns and bootstrapping the
//! application for testing.

use axum_test::{TestServer, TestServerConfig};
use lazy_static::lazy_static;
#[cfg(feature = "with-db")]
use sea_orm::DatabaseConnection;
#[cfg(feature = "with-db")]
use sea_orm_migration::MigratorTrait;

use crate::{
    app::{AppContext, Hooks},
    boot::{self, BootResult},
    Result,
};

// Lazy-static constants for data cleanup patterns
lazy_static! {
    /// Constants for cleaning up user model data, replacing certain patterns with placeholders.
    pub static ref CLEANUP_USER_MODEL: Vec<(&'static str, &'static str)> = vec![
        (
            r"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})",
            "PID"
        ),
        (r"password: (.*{60}),", "password: \"PASSWORD\","),
        (r"([A-Za-z0-9-_]*\.[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*)","TOKEN")
    ];

    /// Constants for cleaning up date data, replacing date-time patterns with placeholders.
    pub static ref CLEANUP_DATE: Vec<(&'static str, &'static str)> =
        vec![
            (r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+", "DATE"),
            (r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", "DATE")
            ];

    /// Constants for cleaning up generals model data, replacing IDs with placeholders.
    pub static ref CLEANUP_MODEL: Vec<(&'static str, &'static str)> = vec![(r"id: \d+,", "id: ID")];
}

/// Combines cleanup filters from various categories (user model, date, and
/// model) into one list. This is used for data cleaning and pattern
/// replacement.
///
/// # Example
///
/// The provided example demonstrates how to efficiently clean up a user model.
/// This process is particularly valuable when you need to capture a snapshot of
/// user model data that includes dynamic elements such as incrementing IDs,
/// automatically generated PIDs, creation/update timestamps, and similar
/// attributes.
///
/// ```rust,ignore
/// use myapp::app::App;
/// use loco_rs::testing;
/// use migration::Migrator;
///
/// #[tokio::test]
/// async fn test_create_user() {
///     let boot = testing::boot_test::<App, Migrator>().await;
///
///     // Create a user and save into the database.
///
///     // capture the snapshot and cleanup the data.
///     with_settings!({
///         filters => testing::cleanup_user_model()
///     }, {
///         assert_debug_snapshot!(saved_user);
///     });
/// }
/// ```
#[must_use]
pub fn cleanup_user_model() -> Vec<(&'static str, &'static str)> {
    let mut combined_filters = CLEANUP_USER_MODEL.to_vec();
    combined_filters.extend(CLEANUP_DATE.iter().copied());
    combined_filters.extend(CLEANUP_MODEL.iter().copied());
    combined_filters
}

#[cfg(feature = "with-db")]
/// Bootstraps test application with test environment hard coded.
///
/// # Errors
/// when could not bootstrap the test environment
///
/// # Example
///
/// The provided example demonstrates how to boot the test case with the
/// application context.
///
/// ```rust,ignore
/// use myapp::app::App;
/// use loco_rs::testing;
/// use migration::Migrator;
///
/// #[tokio::test]
/// async fn test_create_user() {
///     let boot = testing::boot_test::<App, Migrator>().await;
///
///     /// .....
///     assert!(false)
/// }
/// ```
pub async fn boot_test<H: Hooks, M: MigratorTrait>() -> Result<BootResult> {
    boot::create_app::<H, M>(boot::StartMode::ServerOnly, "test").await
}

#[cfg(not(feature = "with-db"))]
pub async fn boot_test<H: Hooks>() -> Result<BootResult> {
    boot::create_app::<H>(boot::StartMode::ServerOnly, "test").await
}

#[cfg(feature = "with-db")]
/// Seeds data into the database.
///
///
/// # Errors
/// When seed fails
///
/// # Example
///
/// The provided example demonstrates how to boot the test case and run seed
/// data.
///
/// ```rust,ignore
/// use myapp::app::App;
/// use loco_rs::testing;
/// use migration::Migrator;
///
/// #[tokio::test]
/// async fn test_create_user() {
///     let boot = testing::boot_test::<App, Migrator>().await;
///     testing::seed::<App>(&boot.app_context.db).await.unwrap();
///
///     /// .....
///     assert!(false)
/// }
/// ```
pub async fn seed<H: Hooks>(db: &DatabaseConnection) -> eyre::Result<()> {
    let path = std::path::Path::new("src/fixtures");
    Ok(H::seed(db, path).await?)
}

#[allow(clippy::future_not_send)]
#[cfg(feature = "with-db")]
/// Initiates a test request with a provided callback.
///
///
/// # Panics
/// When could not initialize the test request.this errors can be when could not
/// initialize the test app
///
/// # Example
///
/// The provided example demonstrates how to create a test that check
/// application HTTP endpoints
///
/// ```rust,ignore
/// use myapp::app::App;
/// use loco_rs::testing;
/// use migration::Migrator;
///
///     #[tokio::test]
/// #[serial]
/// async fn can_register() {
///     testing::request::<App, Migrator, _, _>(|request, ctx| async move {
///         let response = request.post("/auth/register").json(&serde_json::json!({})).await;
///
///         with_settings!({
///             filters => testing::cleanup_user_model()
///         }, {
///             assert_debug_snapshot!(response);
///         });
///     })
///     .await;
/// }
/// ```
pub async fn request<H: Hooks, M: MigratorTrait, F, Fut>(callback: F)
where
    F: FnOnce(TestServer, AppContext) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let boot = boot_test::<H, M>().await.unwrap();

    let config = TestServerConfig::builder()
        .default_content_type("application/json")
        .build();

    let server = TestServer::new_with_config(boot.router.unwrap(), config).unwrap();

    callback(server, boot.app_context.clone()).await;
}

#[cfg(not(feature = "with-db"))]
#[allow(clippy::future_not_send)]
pub async fn request<H: Hooks, F, Fut>(callback: F)
where
    F: FnOnce(TestServer, AppContext) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let boot = boot_test::<H>().await.unwrap();

    let config = TestServerConfig::builder()
        .default_content_type("application/json")
        .build();

    let server = TestServer::new_with_config(boot.router.unwrap(), config).unwrap();

    callback(server, boot.app_context.clone()).await;
}
