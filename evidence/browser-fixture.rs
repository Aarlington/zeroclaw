    #[tokio::test]
    #[ignore = "local browser acceptance fixture"]
    async fn browser_binding_acceptance_harness() {
        let server = Arc::new(idp().await);
        Mock::given(http_method("GET")).and(http_path("/authorize"))
            .respond_with(|request: &wiremock::Request| {
                let q: HashMap<_, _> = request.url.query_pairs().into_owned().collect();
                let callback = format!("{}?code=synthetic-code&state={}", q["redirect_uri"], q["state"]);
                ResponseTemplate::new(200).set_body_raw(format!(
                    "<!doctype html><title>Mock IdP</title><a id=\"finish\" href=\"{}\">Complete test sign-in</a>",
                    callback.replace('&', "&amp;")
                ), "text/html; charset=utf-8")
            }).mount(&server).await;
        Mock::given(http_method("POST")).and(http_path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "synthetic-browser-token", "token_type": "Bearer"
            }))).mount(&server).await;
        let mut state = crate::api::tests::test_state(config_with_alias(&server.uri(), "corp"));
        state.path_prefix = "/gw".into();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let count_server = Arc::clone(&server);
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let stop = Arc::new(parking_lot::Mutex::new(Some(stop_tx)));
        let app = Router::new()
            .nest("/gw", routes().with_state(state))
            .layer(axum::middleware::from_fn(crate::security_headers::apply))
            .route("/__qa/count", get(move || {
                let server = Arc::clone(&count_server);
                async move { Json(serde_json::json!({"token_requests": requests_to(&server, "/token").await})) }
            }))
            .route("/__qa/stop", get(move || async move {
                if let Some(tx) = stop.lock().take() { let _ = tx.send(()); }
                StatusCode::NO_CONTENT
            }));
        let ready = std::env::var("ZC_BINDING_QA_READY").unwrap();
        std::fs::write(ready, format!("http://localhost:{port}")).unwrap();
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
            .with_graceful_shutdown(async { let _ = tokio::time::timeout(Duration::from_secs(300), stop_rx).await; })
            .await.unwrap();
    }
