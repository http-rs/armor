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
