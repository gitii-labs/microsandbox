//! Must-understand local encoding for grants that omit token response fields.

use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser::SerializeSeq};

use crate::OAuthSecret;
use crate::compat::field::Field;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedGrant<T> {
    token_response_omission_v1: T,
}

#[derive(Deserialize)]
struct PlainGrant {
    #[serde(default)]
    token_response_omission_v1: Field<de::IgnoredAny>,
    #[serde(flatten)]
    grant: OAuthSecret,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum StoredGrant {
    Protected(ProtectedGrant<OAuthSecret>),
    Plain(PlainGrant),
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn serialize<S>(grants: &[OAuthSecret], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut sequence = serializer.serialize_seq(Some(grants.len()))?;
    for grant in grants {
        if grant.omit_token_response_fields.is_empty() {
            sequence.serialize_element(grant)?;
        } else {
            // An older reader requires the routing fields at the top level of
            // each grant. It must reject this entry, not silently drop policy.
            sequence.serialize_element(&ProtectedGrant {
                token_response_omission_v1: grant,
            })?;
        }
    }
    sequence.end()
}

pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Vec<OAuthSecret>, D::Error>
where
    D: Deserializer<'de>,
{
    Vec::<StoredGrant>::deserialize(deserializer)?
        .into_iter()
        .map(|grant| match grant {
            StoredGrant::Protected(ProtectedGrant {
                token_response_omission_v1: grant,
            }) if grant.omit_token_response_fields.is_empty() => Err(de::Error::custom(
                "protected OAuth grant requires omitted token response field names",
            )),
            StoredGrant::Protected(ProtectedGrant {
                token_response_omission_v1: grant,
            })
            | StoredGrant::Plain(PlainGrant {
                token_response_omission_v1: Field::Missing,
                grant,
            }) => Ok(grant),
            // Never interpret an invalid protected entry as an ordinary grant.
            StoredGrant::Plain(_) => Err(de::Error::custom("invalid protected OAuth grant")),
        })
        .collect()
}
