//! Local catalog format for desired and active sandbox settings.

use microsandbox_types::SecretsConfig;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::SandboxConfig;
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Older readers, including releases that do not recognize `network.secrets.oauth`,
/// require `network.enabled` to be a boolean. Only opted-in rows use this object.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedNetworkEnabled {
    oauth_token_response_omission_v1: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SandboxConfig {
    /// Decode the local catalog's desired or active configuration JSON.
    pub(crate) fn decode_stored(json: &str) -> MicrosandboxResult<Self> {
        match serde_json::from_str::<Self>(json) {
            Ok(config) if !config.requires_oauth_omission() => Ok(config),
            Ok(_) => Err(MicrosandboxError::InvalidConfig(
                "saved OAuth token response field omission requires a protected network record"
                    .into(),
            )),
            Err(ordinary_error) => {
                let mut value: Value = serde_json::from_str(json)?;
                let Some(enabled) = value
                    .pointer_mut("/network/enabled")
                    .filter(|v| v.is_object())
                else {
                    return Err(ordinary_error.into());
                };
                let marker: ProtectedNetworkEnabled = serde_json::from_value(enabled.take())?;
                *enabled = Value::Bool(marker.oauth_token_response_omission_v1);
                let config: Self = serde_json::from_value(value)?;
                if !config.requires_oauth_omission() {
                    return Err(MicrosandboxError::InvalidConfig(
                        "protected network record requires a saved OAuth token response field omission policy".into(),
                    ));
                }
                Ok(config)
            }
        }
    }

    #[cfg(feature = "local")]
    pub(crate) fn encode_stored(&self) -> MicrosandboxResult<String> {
        if !self.requires_oauth_omission() {
            return Ok(serde_json::to_string(self)?);
        }
        let mut value = serde_json::to_value(self)?;
        value["network"]["enabled"] = serde_json::to_value(ProtectedNetworkEnabled {
            oauth_token_response_omission_v1: self.spec.network.enabled,
        })?;
        Ok(serde_json::to_string(&value)?)
    }

    fn requires_oauth_omission(&self) -> bool {
        self.spec
            .network
            .secrets
            .as_ref()
            .is_some_and(SecretsConfig::has_oauth_token_response_omission)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, feature = "local"))]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn oauth_omission_catalog_encoding_is_per_sandbox() {
        let mut config = SandboxConfig::default();
        config.spec.network.secrets = Some(
            serde_json::from_value(json!({
                "oauth": [{
                    "broker_endpoint": "/synthetic/broker.sock",
                    "grant_id": "fixture",
                    "token_endpoint": "https://provider.invalid/token",
                    "inject_hosts": [{"Exact": "provider.invalid"}],
                    "access_token_field": "access_token",
                    "refresh_token_field": "refresh_token",
                    "access_env_var": "ACCESS",
                    "refresh_env_var": "REFRESH",
                    "access_sentinel": "$ACCESS",
                    "refresh_sentinel": "$REFRESH"
                }]
            }))
            .unwrap(),
        );
        let ordinary = serde_json::to_string(&config).unwrap();

        assert_eq!(config.encode_stored().unwrap(), ordinary);
        assert_eq!(
            SandboxConfig::decode_stored(&ordinary)
                .unwrap()
                .encode_stored()
                .unwrap(),
            ordinary,
        );

        config.spec.network.secrets.as_mut().unwrap().oauth[0].omit_token_response_fields =
            vec!["id_token".into()];
        for enabled in [true, false] {
            config.spec.network.enabled = enabled;
            let plain = serde_json::to_value(&config).unwrap();
            let stored = config.encode_stored().unwrap();
            let mut marker: Value = serde_json::from_str(&stored).unwrap();

            assert_eq!(
                marker["network"]["enabled"],
                json!({"oauth_token_response_omission_v1": enabled})
            );
            assert_eq!(marker["network"]["secrets"], plain["network"]["secrets"]);
            assert!(serde_json::from_str::<SandboxConfig>(&stored).is_err());
            assert!(SandboxConfig::decode_stored(&plain.to_string()).is_err());

            let restored = SandboxConfig::decode_stored(&stored).unwrap();
            assert_eq!(serde_json::to_value(restored).unwrap(), plain);

            let mut unknown_version = marker.clone();
            unknown_version["network"]["enabled"] =
                json!({"oauth_token_response_omission_v2": enabled});
            assert!(SandboxConfig::decode_stored(&unknown_version.to_string()).is_err());

            marker["network"]["secrets"]["oauth"][0]["omit_token_response_fields"] = json!([]);
            assert!(SandboxConfig::decode_stored(&marker.to_string()).is_err());
        }
    }
}
