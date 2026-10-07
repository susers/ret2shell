use std::sync::Arc;

use axum::{
  body::Body,
  http::{Request, Response, StatusCode},
  response::IntoResponse,
};
use prometheus::{Encoder, IntCounterVec, IntGaugeVec, Opts, Registry, TextEncoder};
use tower::Layer;
use tracing::debug;

use super::auth::Token;

/// Prometheus metrics registry for HTTP request metrics.
#[derive(Clone)]
pub struct MetricsRegistry {
  pub registry: Registry,
  /// Total HTTP requests by method, path pattern, status, and key (user ID or
  /// IP).
  pub http_requests_total: IntCounterVec,
  /// Current in-flight requests by key (user ID or IP).
  pub http_requests_in_flight: IntGaugeVec,
}

impl MetricsRegistry {
  pub fn new() -> Result<Self, prometheus::Error> {
    let registry = Registry::new();

    let http_requests_total = IntCounterVec::new(
      Opts::new("http_requests_total", "Total number of HTTP requests"),
      &["method", "path", "status", "key"],
    )?;

    let http_requests_in_flight = IntGaugeVec::new(
      Opts::new(
        "http_requests_in_flight",
        "Current number of HTTP requests being processed",
      ),
      &["key"],
    )?;

    registry.register(Box::new(http_requests_total.clone()))?;
    registry.register(Box::new(http_requests_in_flight.clone()))?;

    Ok(Self {
      registry,
      http_requests_total,
      http_requests_in_flight,
    })
  }

  /// Get the rate limiter key from the request (user ID or IP).
  fn extract_key<B>(req: &Request<B>) -> String {
    // Try to get user ID from token first (matches HybridUserOrIpExtractor
    // logic)
    if let Some(token) = req.extensions().get::<Token>()
      && token.id != 0
    {
      return format!("u:{}", token.id);
    }

    // Fall back to IP address
    if let Some(ip) = crate::middleware::forwarded::get_client_ip(req) {
      return format!("ip:{}", ip);
    }

    "unknown".to_string()
  }
}

impl Default for MetricsRegistry {
  fn default() -> Self {
    Self::new().expect("failed to create metrics registry")
  }
}

/// Layer that adds metrics tracking to requests.
#[derive(Clone)]
pub struct MetricsLayer {
  pub metrics: Arc<MetricsRegistry>,
}

impl<S> Layer<S> for MetricsLayer {
  type Service = MetricsMiddleware<S>;

  fn layer(&self, inner: S) -> Self::Service {
    MetricsMiddleware {
      metrics: self.metrics.clone(),
      inner,
    }
  }
}

/// Middleware that tracks HTTP request metrics per user/IP.
#[derive(Clone)]
pub struct MetricsMiddleware<S> {
  metrics: Arc<MetricsRegistry>,
  inner: S,
}

impl<S, ReqBody> tower::Service<Request<ReqBody>> for MetricsMiddleware<S>
where
  S: tower::Service<Request<ReqBody>, Response = Response<Body>> + Clone + Send + 'static,
  S::Future: Send,
  S::Error: std::fmt::Debug,
  ReqBody: Send + 'static,
{
  type Response = S::Response;
  type Error = S::Error;
  type Future = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
  >;

  fn poll_ready(
    &mut self, cx: &mut std::task::Context<'_>,
  ) -> std::task::Poll<Result<(), Self::Error>> {
    self.inner.poll_ready(cx)
  }

  fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
    let metrics = self.metrics.clone();
    let key = MetricsRegistry::extract_key(&req);
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    // Increment in-flight counter
    metrics
      .http_requests_in_flight
      .with_label_values(&[&key])
      .inc();

    let future = self.inner.call(req);

    Box::pin(async move {
      let response = future.await?;
      let status = response.status();

      // Decrement in-flight counter
      metrics
        .http_requests_in_flight
        .with_label_values(&[&key])
        .dec();

      // Increment total requests counter
      metrics
        .http_requests_total
        .with_label_values(&[method.as_str(), &path, &status.to_string(), &key])
        .inc();

      debug!(
        method = %method,
        path = %path,
        status = %status,
        key = %key,
        "request metrics recorded"
      );

      Ok(response)
    })
  }
}

/// Handler to expose Prometheus metrics endpoint.
pub async fn metrics_handler(metrics: Arc<MetricsRegistry>) -> impl IntoResponse {
  let encoder = TextEncoder::new();
  let metric_families = metrics.registry.gather();

  let mut output = Vec::new();
  if let Err(e) = encoder.encode(&metric_families, &mut output) {
    tracing::error!(error = ?e, "failed to encode metrics");
    return (
      StatusCode::INTERNAL_SERVER_ERROR,
      "failed to encode metrics",
    )
      .into_response();
  }

  let content_type = encoder.format_type().to_string();
  (StatusCode::OK, [("Content-Type", content_type)], output).into_response()
}

#[cfg(test)]
mod tests {
  use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode},
    routing::get,
  };
  use tower::ServiceExt;

  use super::*;
  use crate::middleware::auth::Token;

  #[tokio::test]
  async fn test_metrics_endpoint() {
    let metrics = Arc::new(MetricsRegistry::default());
    let app = Router::new()
      .route(
        "/metrics",
        get({
          let m = metrics.clone();
          move || metrics_handler(m.clone())
        }),
      )
      .route("/test", get(|| async { "ok" }))
      .layer(MetricsLayer {
        metrics: metrics.clone(),
      });

    // Make a test request
    let req = Request::builder()
      .method(Method::GET)
      .uri("/test")
      .body(Body::empty())
      .unwrap();

    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Scrape metrics
    let req = Request::builder()
      .method(Method::GET)
      .uri("/metrics")
      .body(Body::empty())
      .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
      .await
      .unwrap();
    let body_str = String::from_utf8_lossy(&body);

    // Verify metrics are present
    assert!(body_str.contains("http_requests_total"));
    assert!(body_str.contains("http_requests_in_flight"));
  }

  #[tokio::test]
  async fn test_extract_key_uses_user_id_when_authenticated() {
    let mut req = Request::builder().body(()).unwrap();
    req.extensions_mut().insert(Token {
      id: 42,
      account: "alice".to_string(),
      nickname: "Alice".to_string(),
      permissions: Default::default(),
      exp: 0,
    });

    let key = MetricsRegistry::extract_key(&req);
    assert_eq!(key, "u:42");
  }

  #[tokio::test]
  async fn test_extract_key_falls_back_to_ip() {
    use std::net::{Ipv4Addr, SocketAddr};

    use axum::extract::ConnectInfo;

    let mut req = Request::builder().body(()).unwrap();
    req
      .extensions_mut()
      .insert(ConnectInfo(SocketAddr::from((Ipv4Addr::LOCALHOST, 8080))));

    let key = MetricsRegistry::extract_key(&req);
    assert!(key.starts_with("ip:"));
    assert!(key.contains("127.0.0.1"));
  }
}
