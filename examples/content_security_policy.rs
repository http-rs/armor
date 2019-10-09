fn main() {
    let mut headers = http::HeaderMap::new();
    armor::armor(&mut headers);
    let mut csp_policy = armor::ContentSecurityPolicy::new();

    csp_policy
        .default_src(&["'self'", "areweasyncyet.rs"])
        .script_src(&["'self'"])
        .object_src(&["'none'"])
        .upgrade_insecure_requests();

    armor::content_security_policy(&mut headers, csp_policy); // "content-security-policy": "default-src 'self' areweasyncyet.rs; script-src 'self'; object-src 'none'; upgrade-insecure-requests"}

    assert_eq!(headers["content-security-policy"], "default-src 'self' areweasyncyet.rs; script-src 'self'; object-src 'none'; upgrade-insecure-requests");

    println!("{:?}", headers)
    // {"x-dns-prefetch-control": "on", "x-content-type-options": "nosniff", "x-frame-options": "sameorigin", "strict-transport-security": "max-age=5184000", "x-xss-protection": "1; mode=block", "content-security-policy": "default-src 'self' areweasyncyet.rs; script-src 'self'; object-src 'none'; upgrade-insecure-requests"}
}
