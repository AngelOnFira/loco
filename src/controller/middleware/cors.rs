//! Configurable and Flexible CORS Middleware
//!
//! This middleware enables Cross-Origin Resource Sharing (CORS) by allowing
//! configurable origins, methods, and headers in HTTP requests. It can be
//! tailored to fit various application requirements, supporting permissive CORS
//! or specific rules as defined in the middleware configuration.

use std::time::Duration;

use axum::Router as AXRouter;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower_http::cors;

use crate::{app::AppContext, controller::middleware::MiddlewareLayer, Result};

/// CORS middleware configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Cors {
    #[serde(default)]
    pub enable: bool,
    /// Allow origins
    #[serde(default = "default_allow_origins")]
    pub allow_origins: Vec<String>,
    /// Allow headers
    #[serde(default = "default_allow_headers")]
    pub allow_headers: Vec<String>,
    /// Allow methods
    #[serde(default = "default_allow_methods")]
    pub allow_methods: Vec<String>,
    /// Max age
    pub max_age: Option<u64>,
    // Vary headers
    #[serde(default = "default_vary_headers")]
    pub vary: Vec<String>,
}

impl Default for Cors {
    fn default() -> Self {
        serde_json::from_value(json!({})).unwrap()
    }
}

fn default_allow_origins() -> Vec<String> {
    vec!["any".to_string()]
}

fn default_allow_headers() -> Vec<String> {
    vec!["*".to_string()]
}

fn default_allow_methods() -> Vec<String> {
    vec!["*".to_string()]
}

fn default_vary_headers() -> Vec<String> {
    vec![
        "origin".to_string(),
        "access-control-request-method".to_string(),
        "access-control-request-headers".to_string(),
    ]
}

impl Cors {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            enable: true,
            allow_headers: vec![],
            allow_methods: vec![],
            allow_origins: vec![],
            max_age: None,
            vary: vec![],
        }
    }
    /// Creates cors layer
    ///
    /// # Errors
    ///
    /// This function returns an error in the following cases:
    ///
    /// - If any of the provided origins in `allow_origins` cannot be parsed as
    ///   a valid URI, the function will return a parsing error.
    /// - If any of the provided headers in `allow_headers` cannot be parsed as
    ///   valid HTTP headers, the function will return a parsing error.
    /// - If any of the provided methods in `allow_methods` cannot be parsed as
    ///   valid HTTP methods, the function will return a parsing error.
    ///
    /// In all of these cases, the error returned will be the result of the
    /// `parse` method of the corresponding type.
    pub fn cors(&self) -> Result<cors::CorsLayer> {
        let mut cors = cors::CorsLayer::new();

        if self.allow_origins.contains(&"any".to_string()) {
            cors = cors.allow_origin(cors::Any);
        } else if !self.allow_origins.is_empty() {
            let allowed_origins = self.allow_origins.clone();
            // panic!("allowed_origins: {:#?}", allowed_origins);
            // tracing::info!("allowed: {allowed}, origin: {}", origin.to_str().unwrap());
            cors = cors.allow_origin(cors::AllowOrigin::predicate(
                move |origin: &axum::http::HeaderValue,
                      _request_parts: &axum::http::request::Parts| {
                    let origin_str = origin.to_str().unwrap_or_default();
                    allowed_origins.iter().any(|allowed| {
                        let origin_url = url::Url::parse(origin_str).ok();
                        match origin_url {
                            Some(url) => {
                                // Compare host (domain) parts only
                                let host = url.host_str().unwrap_or_default();
                                host == allowed.trim_end_matches('/')
                            }
                            None => origin_str.trim_end_matches('/') == allowed.trim_end_matches('/'),
                        }
                    })
                },
            ));
        }

        if !self.allow_headers.is_empty() {
            let headers = self
                .allow_headers
                .iter()
                .map(|h| h.parse())
                .collect::<Result<Vec<_>, _>>()?;
            cors = cors.allow_headers(headers);
        }

        if !self.allow_methods.is_empty() {
            let methods = self
                .allow_methods
                .iter()
                .map(|m| m.parse())
                .collect::<Result<Vec<_>, _>>()?;
            cors = cors.allow_methods(methods);
        }

        if !self.vary.is_empty() {
            let vary = self
                .vary
                .iter()
                .map(|v| v.parse())
                .collect::<Result<Vec<_>, _>>()?;
            cors = cors.vary(vary);
        }

        if let Some(max_age) = self.max_age {
            cors = cors.max_age(Duration::from_secs(max_age));
        }

        // tracing::info!("cors: {:#?}", cors);
        // panic!("cors");

        Ok(cors)
    }
}

impl MiddlewareLayer for Cors {
    /// Returns the name of the middleware
    fn name(&self) -> &'static str {
        "cors"
    }

    /// Returns whether the middleware is enabled or not
    fn is_enabled(&self) -> bool {
        self.enable
    }

    fn config(&self) -> serde_json::Result<serde_json::Value> {
        serde_json::to_value(self)
    }

    /// Applies the CORS middleware layer to the Axum router.
    fn apply(&self, app: AXRouter<AppContext>) -> Result<AXRouter<AppContext>> {
        Ok(app.layer(self.cors()?))
    }
}

#[cfg(test)]
mod tests {

    use axum::{
        body::Body,
        http::{Method, Request},
        routing::get,
        Router,
    };
    use insta::assert_debug_snapshot;
    use rstest::rstest;
    use tower::ServiceExt;

    use super::*;
    use crate::tests_cfg;

    #[rstest]
    #[case("default", None, None, None)]
    #[case("with_allow_headers", Some(vec!["token".to_string(), "user".to_string()]), None, None)]
    #[case("with_allow_methods", None, Some(vec!["post".to_string(), "get".to_string()]), None)]
    #[case("with_max_age", None, None, Some(20))]
    #[case("default", None, None, None)]
    #[tokio::test]
    async fn cors_enabled(
        #[case] test_name: &str,
        #[case] allow_headers: Option<Vec<String>>,
        #[case] allow_methods: Option<Vec<String>>,
        #[case] max_age: Option<u64>,
    ) {
        let mut middleware = Cors::empty();
        if let Some(allow_headers) = allow_headers {
            middleware.allow_headers = allow_headers;
        }
        if let Some(allow_methods) = allow_methods {
            middleware.allow_methods = allow_methods;
        }
        middleware.max_age = max_age;

        let app = Router::new().route("/", get(|| async {}));
        let app = middleware
            .apply(app)
            .expect("apply middleware")
            .with_state(tests_cfg::app::get_app_context().await);

        let req = Request::builder()
            .uri("/")
            .method(Method::GET)
            .body(Body::empty())
            .expect("request");

        let response = app.oneshot(req).await.expect("valid response");

        assert_debug_snapshot!(
            format!("cors_[{test_name}]"),
            (
                format!(
                    "access-control-allow-origin: {:?}",
                    response.headers().get("access-control-allow-origin")
                ),
                format!("vary: {:?}", response.headers().get("vary")),
                format!(
                    "access-control-allow-methods: {:?}",
                    response.headers().get("access-control-allow-methods")
                ),
                format!(
                    "access-control-allow-headers: {:?}",
                    response.headers().get("access-control-allow-headers")
                ),
                format!("allow: {:?}", response.headers().get("allow")),
            )
        );
    }

    #[test]
    fn should_be_disabled() {
        let middleware = Cors::default();
        assert!(!middleware.is_enabled());
    }
}
