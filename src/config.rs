use std::num::{NonZeroU16, NonZeroUsize};

use serde::Deserialize;

const DEFAULT_LISTEN_HOST: &str = "0.0.0.0";
const DEFAULT_LISTEN_PORT: NonZeroU16 = NonZeroU16::new(28884).unwrap();
const DEFAULT_WEB_WORKERS: NonZeroUsize = NonZeroUsize::new(4).unwrap();
const DEFAULT_HTML_TITLE: &str = "Atlas Transaction Decoder";
const DEFAULT_MAX_INPUT_BYTES: NonZeroUsize = NonZeroUsize::new(2 * 1024 * 1024).unwrap();
// Default chain id used when a request omits `chainId`. Defaults to the Arkiv
// dev chain so the deterministic local provider signer verifies out of the box.
const DEFAULT_CHAIN_ID: u64 = 1337;

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    #[serde(default = "default_listen_host")]
    pub listen_host: String,
    #[serde(default = "default_listen_port")]
    pub listen_port: NonZeroU16,
    #[serde(default = "default_web_workers")]
    pub web_workers: NonZeroUsize,
    #[serde(default = "default_html_title")]
    pub html_title: String,
    #[serde(default = "default_max_input_bytes")]
    pub max_input_bytes: NonZeroUsize,
    #[serde(default = "default_chain_id")]
    pub default_chain_id: u64,
    /// Optional comma-separated 0x-addresses added to the trusted
    /// payload-provider signer allowlist used for reference verification.
    #[serde(default)]
    pub trusted_provider_signers: Option<String>,
}

pub fn create_config() -> Config {
    envy::from_env::<Config>().unwrap_or_else(|err| panic!("invalid config: {err}"))
}

fn default_listen_host() -> String {
    DEFAULT_LISTEN_HOST.to_string()
}

fn default_listen_port() -> NonZeroU16 {
    DEFAULT_LISTEN_PORT
}

fn default_web_workers() -> NonZeroUsize {
    DEFAULT_WEB_WORKERS
}

fn default_html_title() -> String {
    DEFAULT_HTML_TITLE.to_string()
}

fn default_max_input_bytes() -> NonZeroUsize {
    DEFAULT_MAX_INPUT_BYTES
}

fn default_chain_id() -> u64 {
    DEFAULT_CHAIN_ID
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_pairs<const N: usize>(pairs: [(&str, &str); N]) -> Result<Config, envy::Error> {
        envy::from_iter(
            pairs
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string())),
        )
    }

    #[test]
    fn defaults_apply_when_env_is_empty() {
        let config = from_pairs([]).unwrap();
        assert_eq!(config.listen_host, DEFAULT_LISTEN_HOST);
        assert_eq!(config.listen_port, DEFAULT_LISTEN_PORT);
        assert_eq!(config.web_workers, DEFAULT_WEB_WORKERS);
        assert_eq!(config.html_title, DEFAULT_HTML_TITLE);
        assert_eq!(config.max_input_bytes, DEFAULT_MAX_INPUT_BYTES);
        assert_eq!(config.default_chain_id, DEFAULT_CHAIN_ID);
        assert_eq!(config.trusted_provider_signers, None);
    }

    #[test]
    fn parses_valid_overrides() {
        let config = from_pairs([
            ("LISTEN_PORT", "9000"),
            ("HTML_TITLE", "Decoder"),
            ("MAX_INPUT_BYTES", "4096"),
            ("DEFAULT_CHAIN_ID", "42069"),
            ("TRUSTED_PROVIDER_SIGNERS", "0xabc,0xdef"),
        ])
        .unwrap();
        assert_eq!(config.listen_port.get(), 9000);
        assert_eq!(config.html_title, "Decoder");
        assert_eq!(config.max_input_bytes.get(), 4096);
        assert_eq!(config.default_chain_id, 42069);
        assert_eq!(
            config.trusted_provider_signers.as_deref(),
            Some("0xabc,0xdef")
        );
    }

    #[test]
    fn rejects_zero_port() {
        assert!(from_pairs([("LISTEN_PORT", "0")]).is_err());
    }
}
