//! HTTP Security Headers.
//!
//! Adapted from [helmetjs](https://helmetjs.github.io/).
//!
//! ## Example
//! ```
//! let mut headers = http::HeaderMap::new();
//! armor::armor(&mut headers);
//! assert_eq!(headers["X-Content-Type-Options"], "nosniff");
//! assert_eq!(headers["X-XSS-Protection"], "1; mode=block");
//! ```

#![forbid(unsafe_code, future_incompatible, rust_2018_idioms)]
#![deny(missing_debug_implementations, nonstandard_style)]
#![warn(missing_docs, missing_doc_code_examples)]
#![cfg_attr(test, deny(warnings))]

use http::HeaderMap;

/// Apply all protections.
///
/// ## Examples
/// ```
/// let mut headers = http::HeaderMap::new();
/// armor::armor(&mut headers);
/// assert_eq!(headers["X-Content-Type-Options"], "nosniff");
/// assert_eq!(headers["X-XSS-Protection"], "1; mode=block");
/// ```
pub fn armor(headers: &mut HeaderMap) {
    dns_prefetch_control(headers);
    dont_sniff_mimetype(headers);
    frameguard(headers, None);
    hide_powered_by(headers);
    hsts(headers);
    xss_filter(headers);
}

/// Disable browsers’ DNS prefetching by setting the `X-DNS-Prefetch-Control` header.
///
/// [read more](https://helmetjs.github.io/docs/dns-prefetch-control/)
///
/// ## Examples
/// ```
/// let mut headers = http::HeaderMap::new();
/// armor::dns_prefetch_control(&mut headers);
/// assert_eq!(headers["X-DNS-Prefetch-Control"], "on");
/// ```
#[inline]
pub fn dns_prefetch_control(headers: &mut HeaderMap) {
    headers.insert("X-DNS-Prefetch-Control", "on".parse().unwrap());
}

/// Set the frameguard level.
#[derive(Debug, Clone)]
pub enum FrameOptions {
    /// Set to `sameorigin`
    SameOrigin,
    /// Set to `deny`
    Deny,
}

/// Mitigates clickjacking attacks by setting the `X-Frame-Options` header.
///
/// [read more](https://helmetjs.github.io/docs/frameguard/)
///
/// ## Examples
/// ```
/// let mut headers = http::HeaderMap::new();
/// armor::frameguard(&mut headers, None);
/// assert_eq!(headers["X-Frame-Options"], "sameorigin");
/// ```
#[inline]
pub fn frameguard(headers: &mut HeaderMap, guard: Option<FrameOptions>) {
    let kind = match guard {
        None | Some(FrameOptions::SameOrigin) => "sameorigin",
        Some(FrameOptions::Deny) => "deny",
    };
    headers.insert("X-Frame-Options", kind.parse().unwrap());
}

/// Removes the `X-Powered-By` header to make it slightly harder for attackers to see what
/// potentially-vulnerable technology powers your site.
///
/// [read more](https://helmetjs.github.io/docs/hide-powered-by/)
///
/// ## Examples
/// ```
/// let mut headers = http::HeaderMap::new();
/// headers.insert("X-Powered-By", "Tide/Rust".parse().unwrap());
/// armor::hide_powered_by(&mut headers);
/// assert_eq!(headers.get("X-Powered-By"), None);
/// ```
#[inline]
pub fn hide_powered_by(headers: &mut HeaderMap) {
    headers.remove("X-Powered-By");
}

/// Sets the `Strict-Transport-Security` header to keep your users on `HTTPS`.
///
/// Note that the header won’t tell users on HTTP to switch to HTTPS, it will tell HTTPS users to
/// stick around. Defaults to 60 days.
///
/// [read more](https://helmetjs.github.io/docs/hsts/)
///
/// ## Examples
/// ```
/// let mut headers = http::HeaderMap::new();
/// armor::hsts(&mut headers);
/// assert_eq!(headers["Strict-Transport-Security"], "max-age=5184000");
/// ```
#[inline]
pub fn hsts(headers: &mut HeaderMap) {
    let val = "max-age=5184000".parse().unwrap();
    headers.insert("Strict-Transport-Security", val);
}

/// Prevent browsers from trying to guess (“sniff”) the MIME type, which can have security
/// implications.
///
/// [read more](https://helmetjs.github.io/docs/dont-sniff-mimetype/)
///
/// ## Examples
/// ```
/// let mut headers = http::HeaderMap::new();
/// armor::dont_sniff_mimetype(&mut headers);
/// assert_eq!(headers["X-Content-Type-Options"], "nosniff");
/// ```
#[inline]
pub fn dont_sniff_mimetype(headers: &mut HeaderMap) {
    headers.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
}

/// Sets the `X-XSS-Protection` header to prevent reflected XSS attacks.
///
/// [read more](https://helmetjs.github.io/docs/xss-filter/)
///
/// ## Examples
/// ```
/// let mut headers = http::HeaderMap::new();
/// armor::xss_filter(&mut headers);
/// assert_eq!(headers["X-XSS-Protection"], "1; mode=block");
/// ```
#[inline]
pub fn xss_filter(headers: &mut HeaderMap) {
    headers.insert("X-XSS-Protection", "1; mode=block".parse().unwrap());
}

/// Set the Referrer-Policy level
#[derive(Debug, Clone)]
pub enum ReferrerOptions {
    /// Set to "" (default from browser/site)
    Empty,
    /// Set to "no-referrer"
    NoReferrer,
    /// Set to "no-ferffer-when-downgrade" the default 
    NoReferrerDowngrade,
    /// Set to "same-origin"
    SameOrigin,
    /// Set to "origin"
    Origin,
    /// Set to "strict-origin"
    StrictOrigin,
    /// Set to "origin-when-cross-origin"
    CrossOrigin,
    /// Set to "strict-origin-when-cross-origin"
    StrictCrossOrigin,
    /// Set to "unsafe-url"
    UnsafeUrl,
}

/// Mitigates referrer leakage by controlling the referer[sic] header in links away from pages
/// 
/// [read more](https://scotthelme.co.uk/a-new-security-header-referrer-policy/)
///
/// [Mozilla Developer Network](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy)
///
/// The default value for most browsers/sites is `no-referrer-when-downgrade` setting
/// the header with `ReferrerOptions::Empty` or `None` will default to the site/browsers options
///
/// ## Examples
/// ```
/// let mut headers = http::HeaderMap::new();
/// armor::referrer_policy(&mut headers, Some(ReferrerOptions::UnsafeUrl));
/// armor::referrer_policy(&mut headers, Some(ReferrerOptions::NoReferrer));
/// let mut referrerValues: Vec<&str> = headers.get_all("Referrer-Policy").iter().map(|x| x.to_str().unwrap()).collect();
/// assert_eq!(referrerValues.sort(), vec!("unsafe-url", "no-referrer").sort());
/// ```
#[inline]
pub fn referrer_policy(headers: &mut HeaderMap, referrer: Option<ReferrerOptions>) {
    let policy = match referrer {
        None | Some(ReferrerOptions::Empty) => "",
        Some(ReferrerOptions::NoReferrer) => "no-referrer",
        Some(ReferrerOptions::NoReferrerDowngrade) => "no-referrer-when-downgrade",
        Some(ReferrerOptions::SameOrigin) => "same-origin",
        Some(ReferrerOptions::Origin) => "origin",
        Some(ReferrerOptions::StrictOrigin) => "strict-origin",
        Some(ReferrerOptions::CrossOrigin) => "origin-when-cross-origin",
        Some(ReferrerOptions::StrictCrossOrigin) => "strict-origin-when-cross-origin",
        Some(ReferrerOptions::UnsafeUrl) => "unsafe-url"
    };

    // Allowing for multiple Referrer-Policy headers to be set
    // [Spec](https://w3c.github.io/webappsec-referrer-policy/#unknown-policy-values) Example #13
    if headers.contains_key("Referrer-Policy") {
        headers.append("Referrer-Policy", policy.parse().unwrap());
    } else {
        headers.insert("Referrer-Policy", policy.parse().unwrap());
    }
}
