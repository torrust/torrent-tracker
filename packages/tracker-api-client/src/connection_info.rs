use std::str::FromStr;

use thiserror::Error;
use url::Url;

#[derive(Clone)]
pub struct ConnectionInfo {
    pub origin: Origin,
    pub api_token: Option<String>,
}

impl ConnectionInfo {
    #[must_use]
    pub fn authenticated(origin: Origin, api_token: &str) -> Self {
        Self {
            origin,
            api_token: Some(api_token.to_string()),
        }
    }

    #[must_use]
    pub fn anonymous(origin: Origin) -> Self {
        Self { origin, api_token: None }
    }
}

/// Represents the origin of a HTTP request.
///
/// The format of the origin is a URL, but only the scheme, host, and port are used.
///
/// Pattern: `scheme://host:port/`
#[derive(Debug, Clone)]
pub struct Origin {
    url: Url,
}

#[derive(Debug, Error)]
pub enum OriginError {
    #[error("Invalid URL: {0}")]
    InvalidUrl(#[from] url::ParseError),

    #[error("URL is missing scheme or host")]
    InvalidOrigin,

    #[error("Invalid URL scheme, only http and https are supported")]
    InvalidScheme,
}

impl FromStr for Origin {
    type Err = OriginError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut url = Url::parse(s).map_err(OriginError::InvalidUrl)?;

        // Ensure the URL has a scheme and host
        if url.scheme().is_empty() || url.host().is_none() {
            return Err(OriginError::InvalidOrigin);
        }

        if url.scheme() != "http" && url.scheme() != "https" {
            return Err(OriginError::InvalidScheme);
        }

        // Retain only the origin components
        url.set_path("/");
        url.set_query(None);
        url.set_fragment(None);

        Ok(Origin { url })
    }
}

impl std::fmt::Display for Origin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.url)
    }
}

impl Origin {
    /// # Errors
    ///
    /// Will return an error if the string is not a valid URL containing a
    /// scheme and host.
    pub fn new(s: &str) -> Result<Self, OriginError> {
        s.parse()
    }

    #[must_use]
    pub fn url(&self) -> &Url {
        &self.url
    }
}

#[cfg(test)]
mod tests {
    mod origin {
        use crate::connection_info::Origin;

        #[test]
        fn should_be_parsed_from_a_string_representing_a_url() {
            let origin = Origin::new("https://example.com:8080/path?query#fragment").unwrap();

            assert_eq!(origin.to_string(), "https://example.com:8080/");
        }

        mod when_parsing_from_url_string {
            use crate::connection_info::Origin;

            #[test]
            fn should_ignore_default_ports() {
                let origin = Origin::new("http://example.com:80").unwrap(); // DevSkim: ignore DS137138
                assert_eq!(origin.to_string(), "http://example.com/"); // DevSkim: ignore DS137138

                let origin = Origin::new("https://example.com:443").unwrap();
                assert_eq!(origin.to_string(), "https://example.com/");
            }

            #[test]
            fn should_add_the_slash_after_the_host() {
                let origin = Origin::new("https://example.com:1212").unwrap();

                assert_eq!(origin.to_string(), "https://example.com:1212/");
            }

            #[test]
            fn should_remove_extra_path_and_query_parameters() {
                let origin = Origin::new("https://example.com:1212/path/to/resource?query=1#fragment").unwrap();

                assert_eq!(origin.to_string(), "https://example.com:1212/");
            }

            #[test]
            fn should_fail_when_the_scheme_is_missing() {
                let result = Origin::new("example.com");

                assert!(result.is_err());
            }

            #[test]
            fn should_fail_when_the_scheme_is_not_supported() {
                let result = Origin::new("udp://example.com");

                assert!(result.is_err());
            }

            #[test]
            fn should_fail_when_the_host_is_missing() {
                let result = Origin::new("http://");

                assert!(result.is_err());
            }
        }
    }
}
