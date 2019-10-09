use serde::Serialize;

// Define `report-to` directive value
// [MDN | report-to] https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/report-to
#[derive(Serialize, Debug)]
pub struct ReportTo {
    #[serde(skip_serializing_if = "Option::is_none")]
    group: Option<String>,
    max_age: i32,
    endpoints: Vec<ReportToEndpoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    include_subdomains: Option<bool>,
}

// Define `endpoints` for `report-to` directive value
// [MDN | report-to] https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/report-to
#[derive(Serialize, Debug)]
pub struct ReportToEndpoint {
    url: String,
}

/// Build the Content-Security-Policy
#[derive(Debug)]
pub struct ContentSecurityPolicy {
    directives: Vec<String>,
    report_only_flag: bool,
}

impl Default for ContentSecurityPolicy {
    /// Sets the Content-Security-Policy default to "script-src 'self'; object-src 'self'"
    fn default() -> Self {
        let policy = String::from("script-src 'self'; object-src 'self'");
        ContentSecurityPolicy {
            directives: vec![policy],
            report_only_flag: false,
        }
    }
}

impl ContentSecurityPolicy {
    /// Instantiates ContentSecurityPolicy
    pub fn new() -> ContentSecurityPolicy {
        ContentSecurityPolicy {
            directives: Vec::new(),
            report_only_flag: false,
        }
    }

    /// Defines the Content-Security-Policy `base-uri` directive
    /// [MDN | base-uri](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/base-uri)
    pub fn base_uri(&mut self, sources: &[&str]) -> &mut ContentSecurityPolicy {
        let policy = format!("base-uri {}", sources.join(" "));
        self.directives.push(policy);
        self
    }

    /// Defines the Content-Security-Policy `block-all-mixed-content` directive
    /// [MDN | block-all-mixed-content](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/block-all-mixed-content)
    pub fn block_all_mixed_content(&mut self) -> &mut ContentSecurityPolicy {
        let policy = String::from("block-all-mixed-content");
        self.directives.push(policy);
        self
    }

    /// Defines the Content-Security-Policy `connect-src` directive
    /// [MDN | connect-src](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/connect-src)
    pub fn connect_src(&mut self, sources: &[&str]) -> &mut ContentSecurityPolicy {
        let policy = format!("connect-src {}", sources.join(" "));
        self.directives.push(policy);
        self
    }

    /// Defines the Content-Security-Policy `default-src` directive
    /// [MDN | default-src](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/default-src)
    pub fn default_src(&mut self, sources: &[&str]) -> &mut ContentSecurityPolicy {
        let policy = format!("default-src {}", sources.join(" "));
        self.directives.push(policy);
        self
    }

    /// Defines the Content-Security-Policy `font-src` directive
    /// [MDN | font-src](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/font-src)
    pub fn font_src(&mut self, sources: &[&str]) -> &mut ContentSecurityPolicy {
        let policy = format!("font-src {}", sources.join(" "));
        self.directives.push(policy);
        self
    }

    /// Defines the Content-Security-Policy `form-action` directive
    /// [MDN | form-action](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/form-action)
    pub fn form_action(&mut self, sources: &[&str]) -> &mut ContentSecurityPolicy {
        let policy = format!("form-action {}", sources.join(" "));
        self.directives.push(policy);
        self
    }

    /// Defines the Content-Security-Policy `frame-ancestors` directive
    /// [MDN | frame-ancestors](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors)
    pub fn frame_ancestors(&mut self, sources: &[&str]) -> &mut ContentSecurityPolicy {
        let policy = format!("frame-ancestors {}", sources.join(" "));
        self.directives.push(policy);
        self
    }

    /// Defines the Content-Security-Policy `frame-src` directive
    /// [MDN | frame-src](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-src)
    pub fn frame_src(&mut self, sources: &[&str]) -> &mut ContentSecurityPolicy {
        let policy = format!("frame-src {}", sources.join(" "));
        self.directives.push(policy);
        self
    }

    /// Defines the Content-Security-Policy `img-src` directive
    /// [MDN | img-src](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/img-src)
    pub fn img_src(&mut self, sources: &[&str]) -> &mut ContentSecurityPolicy {
        let policy = format!("img-src {}", sources.join(" "));
        self.directives.push(policy);
        self
    }

    /// Defines the Content-Security-Policy `media-src` directive
    /// [MDN | media-src](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/media-src)
    pub fn media_src(&mut self, sources: &[&str]) -> &mut ContentSecurityPolicy {
        let policy = format!("media-src {}", sources.join(" "));
        self.directives.push(policy);
        self
    }

    /// Defines the Content-Security-Policy `object-src` directive
    /// [MDN | object-src](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/object-src)
    pub fn object_src(&mut self, sources: &[&str]) -> &mut ContentSecurityPolicy {
        let policy = format!("object-src {}", sources.join(" "));
        self.directives.push(policy);
        self
    }

    /// Defines the Content-Security-Policy `plugin-types` directive
    /// [MDN | plugin-types](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/plugin-types)
    pub fn plugin_types(&mut self, sources: &[&str]) -> &mut ContentSecurityPolicy {
        let policy = format!("plugin-types {}", sources.join(" "));
        self.directives.push(policy);
        self
    }

    /// Defines the Content-Security-Policy `require-sri-for` directive
    /// [MDN | require-sri-for](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/require-sri-for)
    pub fn require_sri_for(&mut self, sources: &[&str]) -> &mut ContentSecurityPolicy {
        let policy = format!("require-sri-for {}", sources.join(" "));
        self.directives.push(policy);
        self
    }

    /// Defines the Content-Security-Policy `report-uri` directive
    /// [MDN | report-uri](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/report-uri)
    pub fn report_uri(&mut self, uri: &str) -> &mut ContentSecurityPolicy {
        let policy = format!("report-uri {}", uri);
        self.directives.push(policy);
        self
    }

    /// Defines the Content-Security-Policy `report-to` directive
    /// [MDN | report-to](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/report-to)
    pub fn report_to(&mut self, endpoints: Vec<ReportTo>) -> &mut ContentSecurityPolicy {
        for endpoint in endpoints.iter() {
            match serde_json::to_string(&endpoint) {
                Ok(json) => {
                    let policy = format!("report-to {}", json);
                    self.directives.push(policy);
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
    pub fn sandbox(&mut self, sources: &[&str]) -> &mut ContentSecurityPolicy {
        let policy = format!("sandbox {}", sources.join(" "));
        self.directives.push(policy);
        self
    }

    /// Defines the Content-Security-Policy `script-src` directive
    /// [MDN | script-src](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src)
    pub fn script_src(&mut self, sources: &[&str]) -> &mut ContentSecurityPolicy {
        let policy = format!("script-src {}", sources.join(" "));
        self.directives.push(policy);
        self
    }

    /// Defines the Content-Security-Policy `style-src` directive
    /// [MDN | style-src](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/style-src)
    pub fn style_src(&mut self, sources: &[&str]) -> &mut ContentSecurityPolicy {
        let policy = format!("style-src {}", sources.join(" "));
        self.directives.push(policy);
        self
    }

    /// Defines the Content-Security-Policy `upgrade-insecure-requests` directive
    /// [MDN | upgrade-insecure-requests](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/upgrade-insecure-requests)
    pub fn upgrade_insecure_requests(&mut self) -> &mut ContentSecurityPolicy {
        let policy = String::from("upgrade-insecure-requests");
        self.directives.push(policy);
        self
    }

    /// Defines the Content-Security-Policy `worker-src` directive
    /// [MDN | worker-src](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/worker-src)
    pub fn worker_src(&mut self, sources: &[&str]) -> &mut ContentSecurityPolicy {
        let policy = format!("worker-src {}", sources.join(" "));
        self.directives.push(policy);
        self
    }

    /// Change the header to `Content-Security-Policy-Report-Only`
    pub fn report_only(&mut self) -> &mut ContentSecurityPolicy {
        self.report_only_flag = true;
        self
    }

    /// Retrieve the `report_only_flag` flag
    pub fn report(&self) -> bool {
        self.report_only_flag
    }

    /// Retrieve the policy value
    pub fn value(&self) -> String {
        self.directives.join("; ")
    }
}
