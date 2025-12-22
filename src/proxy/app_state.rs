use std::collections::HashMap;

use url::Url;

use crate::config::{Config, ConfigError, TokenMapping};

#[derive(Debug, Clone)]
pub struct AppState {
    pub upstream_url: Url,
    pub tokens: HashMap<String, String>,
    pub client: reqwest::Client,
}

impl TryFrom<Config> for AppState {
    type Error = ConfigError;

    fn try_from(config: Config) -> Result<Self, Self::Error> {
        Ok(Self {
            upstream_url: Url::parse(&config.upstream.url)
                .map_err(|_| ConfigError::InvalidUrl(config.upstream.url.clone()))?,
            tokens: config
                .auth
                .tokens
                .into_iter()
                .map(|token| token.try_into())
                .collect::<Result<HashMap<String, String>, ConfigError>>()?,
            client: reqwest::Client::builder().no_proxy().build()?,
        })
    }
}

impl TryFrom<TokenMapping> for (String, String) {
    type Error = ConfigError;

    fn try_from(token: TokenMapping) -> Result<Self, Self::Error> {
        if token.client.is_empty() || token.upstream.is_empty() {
            Err(ConfigError::InvalidToken(format!(
                "Token mapping contains empty value: client: \"{client:?}\" upstream: \"{upstream:?}\"",
                client = token.client,
                upstream = token.upstream,
            )))
        } else {
            Ok((token.client.clone(), token.upstream.clone()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthConfig, ServerConfig, UpstreamConfig};

    fn create_test_config(tokens: Vec<TokenMapping>) -> Config {
        Config {
            server: ServerConfig {
                address: "127.0.0.1:8080".to_string(),
            },
            upstream: UpstreamConfig {
                url: "https://api.example.com".to_string(),
            },
            auth: AuthConfig { tokens },
        }
    }

    #[test]
    fn test_app_state_from_valid_config() {
        let config = create_test_config(vec![
            TokenMapping {
                client: "client_token_1".to_string(),
                upstream: "upstream_token_1".to_string(),
            },
            TokenMapping {
                client: "client_token_2".to_string(),
                upstream: "upstream_token_2".to_string(),
            },
        ]);

        let app_state = AppState::try_from(config).unwrap();

        assert_eq!(
            app_state.upstream_url,
            Url::parse("https://api.example.com").unwrap()
        );
        assert_eq!(app_state.tokens.len(), 2);
        assert_eq!(
            app_state.tokens.get("client_token_1"),
            Some(&"upstream_token_1".to_string())
        );
        assert_eq!(
            app_state.tokens.get("client_token_2"),
            Some(&"upstream_token_2".to_string())
        );
    }

    #[test]
    fn test_app_state_from_config_with_empty_tokens() {
        let config = create_test_config(vec![]);

        let app_state = AppState::try_from(config).unwrap();

        assert_eq!(
            app_state.upstream_url,
            Url::parse("https://api.example.com").unwrap()
        );
        assert!(app_state.tokens.is_empty());
    }

    #[test]
    fn test_app_state_from_config_with_invalid_token() {
        let config = create_test_config(vec![TokenMapping {
            client: "".to_string(),
            upstream: "upstream_token".to_string(),
        }]);

        let result = AppState::try_from(config);

        assert!(result.is_err());
        assert!(matches!(result, Err(ConfigError::InvalidToken(_))));
    }

    #[test]
    fn test_token_mapping_try_from_valid() {
        let token = TokenMapping {
            client: "client_key".to_string(),
            upstream: "upstream_key".to_string(),
        };

        let result: Result<(String, String), ConfigError> = token.try_into();

        assert!(result.is_ok());
        let (client, upstream) = result.unwrap();
        assert_eq!(client, "client_key");
        assert_eq!(upstream, "upstream_key");
    }

    #[test]
    fn test_token_mapping_try_from_empty_client() {
        let token = TokenMapping {
            client: "".to_string(),
            upstream: "upstream_key".to_string(),
        };

        let result: Result<(String, String), ConfigError> = token.try_into();

        assert!(result.is_err());
        if let Err(ConfigError::InvalidToken(msg)) = result {
            assert!(msg.contains("empty value"));
        } else {
            panic!("Expected InvalidToken error");
        }
    }

    #[test]
    fn test_token_mapping_try_from_empty_upstream() {
        let token = TokenMapping {
            client: "client_key".to_string(),
            upstream: "".to_string(),
        };

        let result: Result<(String, String), ConfigError> = token.try_into();

        assert!(result.is_err());
        if let Err(ConfigError::InvalidToken(msg)) = result {
            assert!(msg.contains("empty value"));
        } else {
            panic!("Expected InvalidToken error");
        }
    }

    #[test]
    fn test_token_mapping_try_from_both_empty() {
        let token = TokenMapping {
            client: "".to_string(),
            upstream: "".to_string(),
        };

        let result: Result<(String, String), ConfigError> = token.try_into();

        assert!(result.is_err());
        assert!(matches!(result, Err(ConfigError::InvalidToken(_))));
    }
}
