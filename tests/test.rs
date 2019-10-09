use std::error::Error;

#[test]
fn should_work() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    Ok(())
}

#[test]
fn csp_test() {
    let mut headers = http::HeaderMap::new();
    armor::armor(&mut headers);
    let mut csp_policy = armor::ContentSecurityPolicy::new();

    csp_policy
        .default_src(&["'self'", "areweasyncyet.rs"])
        .script_src(&["'self'", "'unsafe-inline'"])
        .object_src(&["'none'"])
        .base_uri(&["'none'"])
        .upgrade_insecure_requests();

    armor::content_security_policy(&mut headers, csp_policy);

    assert_eq!(headers["content-security-policy"], "default-src 'self' areweasyncyet.rs; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; upgrade-insecure-requests");
}
