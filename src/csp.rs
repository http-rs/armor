//! Sets the `Content-Security-Policy` (CSP) HTTP header to prevent cross-site injections
//!
//! [read more](https://helmetjs.github.io/docs/csp/)
//!
//! [Mozilla Developer Network](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy)
//!
//!
//! ## Examples
//! ```
//! let mut policy = armor::csp::new();
//! policy
//!     .default_src(armor::csp::Source::SameOrigin)
//!     .default_src("areweasyncyet.rs")
//!     .script_src(armor::csp::Source::SameOrigin)
//!     .object_src(armor::csp::Source::None)
//!     .base_uri(armor::csp::Source::None)
//!     .upgrade_insecure_requests();
//! let mut headers = http::HeaderMap::new();
//! armor::armor(&mut headers);
//! policy.apply(&mut headers);
//! assert_eq!(headers["content-security-policy"], "base-uri 'none'; default-src 'self' areweasyncyet.rs; object-src 'none'; script-src 'self'; upgrade-insecure-requests");
//! ```

use http::HeaderMap;
use serde::Serialize;
use std::collections::HashMap;
use std::fmt;

/// Define source value
/// [read more](https://content-security-policy.com)
#[derive(Debug)]
pub enum Source {
    /// Set source `'self'`
    SameOrigin,
    /// Set source `'src'`
    SRC,
    /// Set source `'none'`
    None,
    /// Set source `'unsafe-inline'`
    UnsafeInline,
    /// Set source `data:`
    Data,
    /// Set source `mediastream:`
    Mediastream,
    /// Set source `https:`
    HTTPS,
    /// Set source `blob:`
    Blob,
    /// Set source `filesystem:`
    Filesystem,
    /// Set source `'strict-dynamic'`
    StrictDynamic,
    /// Set source `'unsafe-eval'`
    UnsafeEval,
    /// Set source `*`
    Wildcard,
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Source::SameOrigin => write!(f, "'self'"),
            Source::SRC => write!(f, "'src'"),
            Source::None => write!(f, "'none'"),
            Source::UnsafeInline => write!(f, "'unsafe-inline'"),
            Source::Data => write!(f, "data:"),
            Source::Mediastream => write!(f, "mediastream:"),
            Source::HTTPS => write!(f, "https:"),
            Source::Blob => write!(f, "blob:"),
            Source::Filesystem => write!(f, "filesystem:"),
            Source::StrictDynamic => write!(f, "'strict-dynamic'"),
            Source::UnsafeEval => write!(f, "'unsafe-eval'"),
            Source::Wildcard => write!(f, "*"),
        }
    }
}

impl AsRef<str> for Source {
    fn as_ref(&self) -> &str {
        match *self {
            Source::SameOrigin => "'self'",
            Source::SRC => "'src'",
            Source::None => "'none'",
            Source::UnsafeInline => "'unsafe-inline'",
            Source::Data => "data:",
            Source::Mediastream => "mediastream:",
            Source::HTTPS => "https:",
            Source::Blob => "blob:",
            Source::Filesystem => "filesystem:",
            Source::StrictDynamic => "'strict-dynamic'",
            Source::UnsafeEval => "'unsafe-eval'",
            Source::Wildcard => "*",
        }
    }
}

/// Define `report-to` directive value
/// [MDN | report-to](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/report-to)
#[derive(Serialize, Debug)]
pub struct ReportTo {
    #[serde(skip_serializing_if = "Option::is_none")]
    group: Option<String>,
    max_age: i32,
    endpoints: Vec<ReportToEndpoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    include_subdomains: Option<bool>,
}

/// Define `endpoints` for `report-to` directive value
/// [MDN | report-to](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/report-to)
#[derive(Serialize, Debug)]
pub struct ReportToEndpoint {
    url: String,
}

/// Build the Content-Security-Policy
#[derive(Debug)]
pub struct ContentSecurityPolicy {
    policy: Vec<String>,
    report_only_flag: bool,
    directives: HashMap<String, Vec<String>>,
}

impl Default for ContentSecurityPolicy {
    /// Sets the Content-Security-Policy default to "script-src 'self'; object-src 'self'"
    fn default() -> Self {
        let policy = String::from("script-src 'self'; object-src 'self'");
        ContentSecurityPolicy {
            policy: vec![policy],
            report_only_flag: false,
            directives: HashMap::new(),
        }
    }
}

impl ContentSecurityPolicy {
    /// Instantiates ContentSecurityPolicy
    pub fn new() -> ContentSecurityPolicy {
        ContentSecurityPolicy {
            policy: Vec::new(),
            report_only_flag: false,
            directives: HashMap::new(),
        }
    }

    fn insert_directive<T: AsRef<str>>(&mut self, directive: &str, source: T) {
        let directive = String::from(directive);
        let directives = self.directives.entry(directive).or_insert_with(Vec::new);
        let source: String = source.as_ref().to_string();
        directives.push(source);
    }

    /// Defines the Content-Security-Policy `base-uri` directive
    /// [MDN | base-uri](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/base-uri)
    pub fn base_uri<T: AsRef<str>>(&mut self, source: T) -> &mut ContentSecurityPolicy {
        self.insert_directive("base-uri", source);
        self
    }

    /// Defines the Content-Security-Policy `block-all-mixed-content` directive
    /// [MDN | block-all-mixed-content](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/block-all-mixed-content)
    pub fn block_all_mixed_content(&mut self) -> &mut ContentSecurityPolicy {
        let policy = String::from("block-all-mixed-content");
        self.policy.push(policy);
        self
    }

    /// Defines the Content-Security-Policy `connect-src` directive
    /// [MDN | connect-src](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/connect-src)
    pub fn connect_src<T: AsRef<str>>(&mut self, source: T) -> &mut ContentSecurityPolicy {
        self.insert_directive("connect-src", source);
        self
    }

    /// Defines the Content-Security-Policy `default-src` directive
    /// [MDN | default-src](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/default-src)
    pub fn default_src<T: AsRef<str>>(&mut self, source: T) -> &mut ContentSecurityPolicy {
        self.insert_directive("default-src", source);
        self
    }

    /// Defines the Content-Security-Policy `font-src` directive
    /// [MDN | font-src](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/font-src)
    pub fn font_src<T: AsRef<str>>(&mut self, source: T) -> &mut ContentSecurityPolicy {
        self.insert_directive("font-src", source);
        self
    }

    /// Defines the Content-Security-Policy `form-action` directive
    /// [MDN | form-action](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/form-action)
    pub fn form_action<T: AsRef<str>>(&mut self, source: T) -> &mut ContentSecurityPolicy {
        self.insert_directive("form-action", source);
        self
    }

    /// Defines the Content-Security-Policy `frame-ancestors` directive
    /// [MDN | frame-ancestors](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors)
    pub fn frame_ancestors<T: AsRef<str>>(&mut self, source: T) -> &mut ContentSecurityPolicy {
        self.insert_directive("frame-ancestors", source);
        self
    }

    /// Defines the Content-Security-Policy `frame-src` directive
    /// [MDN | frame-src](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-src)
    pub fn frame_src<T: AsRef<str>>(&mut self, source: T) -> &mut ContentSecurityPolicy {
        self.insert_directive("frame-src", source);
        self
    }

    /// Defines the Content-Security-Policy `img-src` directive
    /// [MDN | img-src](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/img-src)
    pub fn img_src<T: AsRef<str>>(&mut self, source: T) -> &mut ContentSecurityPolicy {
        self.insert_directive("img-src", source);
        self
    }

    /// Defines the Content-Security-Policy `media-src` directive
    /// [MDN | media-src](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/media-src)
    pub fn media_src<T: AsRef<str>>(&mut self, source: T) -> &mut ContentSecurityPolicy {
        self.insert_directive("media-src", source);
        self
    }

    /// Defines the Content-Security-Policy `object-src` directive
    /// [MDN | object-src](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/object-src)
    pub fn object_src<T: AsRef<str>>(&mut self, source: T) -> &mut ContentSecurityPolicy {
        self.insert_directive("object-src", source);
        self
    }

    /// Defines the Content-Security-Policy `plugin-types` directive
    /// [MDN | plugin-types](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/plugin-types)
    pub fn plugin_types<T: AsRef<str>>(&mut self, source: T) -> &mut ContentSecurityPolicy {
        self.insert_directive("plugin-types", source);
        self
    }

    /// Defines the Content-Security-Policy `require-sri-for` directive
    /// [MDN | require-sri-for](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/require-sri-for)
    pub fn require_sri_for<T: AsRef<str>>(&mut self, source: T) -> &mut ContentSecurityPolicy {
        self.insert_directive("require-sri-for ", source);
        self
    }

    /// Defines the Content-Security-Policy `report-uri` directive
    /// [MDN | report-uri](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/report-uri)
    pub fn report_uri<T: AsRef<str>>(&mut self, uri: T) -> &mut ContentSecurityPolicy {
        self.insert_directive("report-uri", uri);
        self
    }

    /// Defines the Content-Security-Policy `report-to` directive
    /// [MDN | report-to](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/report-to)
    pub fn report_to(&mut self, endpoints: Vec<ReportTo>) -> &mut ContentSecurityPolicy {
        for endpoint in endpoints.iter() {
            match serde_json::to_string(&endpoint) {
                Ok(json) => {
                    let policy = format!("report-to {}", json);
                    self.policy.push(policy);
                }
                Err(error) => {
                    println!("{:?}", error);
                }
            }
        }
        self
    }

    /// Defines the Content-Security-Policy `sandbox` directive
    /// [MDN | sandbox](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/sandbox)
    pub fn sandbox<T: AsRef<str>>(&mut self, source: T) -> &mut ContentSecurityPolicy {
        self.insert_directive("sandbox", source);
        self
    }

    /// Defines the Content-Security-Policy `script-src` directive
    /// [MDN | script-src](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src)
    pub fn script_src<T: AsRef<str>>(&mut self, source: T) -> &mut ContentSecurityPolicy {
        self.insert_directive("script-src", source);
        self
    }

    /// Defines the Content-Security-Policy `style-src` directive
    /// [MDN | style-src](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/style-src)
    pub fn style_src<T: AsRef<str>>(&mut self, source: T) -> &mut ContentSecurityPolicy {
        self.insert_directive("style-src", source);
        self
    }

    /// Defines the Content-Security-Policy `upgrade-insecure-requests` directive
    /// [MDN | upgrade-insecure-requests](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/upgrade-insecure-requests)
    pub fn upgrade_insecure_requests(&mut self) -> &mut ContentSecurityPolicy {
        let policy = String::from("upgrade-insecure-requests");
        self.policy.push(policy);
        self
    }

    /// Defines the Content-Security-Policy `worker-src` directive
    /// [MDN | worker-src](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/worker-src)
    pub fn worker_src<T: AsRef<str>>(&mut self, source: T) -> &mut ContentSecurityPolicy {
        self.insert_directive("worker-src", source);
        self
    }

    /// Change the header to `Content-Security-Policy-Report-Only`
    pub fn report_only(&mut self) -> &mut ContentSecurityPolicy {
        self.report_only_flag = true;
        self
    }

    /// Create and retrieve the policy value
    fn value(&mut self) -> String {
        for (directive, sources) in &self.directives {
            let policy = format!("{} {}", directive, sources.join(" "));
            self.policy.push(policy);
            self.policy.sort();
        }
        self.policy.join("; ")
    }

    /// Sets the `Content-Security-Policy` (CSP) HTTP header to prevent cross-site injections
    pub fn apply(&mut self, headers: &mut HeaderMap) {
        let val = self.value().parse().unwrap();
        if !self.report_only_flag {
            headers.insert("Content-Security-Policy", val);
        } else {
            headers.insert("Content-Security-Policy-Report-Only", val);
        }
    }
}

/// Instantiates ContentSecurityPolicy
pub fn new() -> ContentSecurityPolicy {
    ContentSecurityPolicy {
        policy: Vec::new(),
        report_only_flag: false,
        directives: HashMap::new(),
    }
}
