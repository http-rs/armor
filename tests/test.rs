use armor::csp;
use std::error::Error;

#[test]
fn should_work() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    Ok(())
}

#[test]
fn csp_test() {
    let mut policy = armor::csp::new();
    policy
        .default_src(csp::Source::SameOrigin)
        .default_src("areweasyncyet.rs")
        .script_src(csp::Source::SameOrigin)
        .script_src(csp::Source::UnsafeInline)
        .object_src(csp::Source::None)
        .base_uri(csp::Source::None)
        .upgrade_insecure_requests();
    let mut headers = http::HeaderMap::new();
    armor::armor(&mut headers);
    policy.apply(&mut headers);

    assert_eq!(headers["content-security-policy"], "base-uri 'none'; default-src 'self' areweasyncyet.rs; object-src 'none'; script-src 'self' 'unsafe-inline'; upgrade-insecure-requests");
}
