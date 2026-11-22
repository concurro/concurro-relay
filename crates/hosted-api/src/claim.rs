//! Exchange-issued session claims and their Ed25519 compact JWS codec.

use std::collections::HashMap;

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

/// The only issuer the hosted verifier accepts.
pub const ISSUER: &str = "concurro-exchange";

/// Authority for one session to use one exact registered credential.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct SessionClaim {
    /// Unique claim identifier.
    pub jti: String,
    /// Issuer, always concurro-exchange.
    pub iss: String,
    /// Exchange session ID.
    pub sub: String,
    /// Issue time in Unix seconds.
    pub iat: i64,
    /// Session deadline in Unix seconds.
    pub exp: i64,
    /// Approved relay ID.
    pub relay_id: String,
    /// Approved owner ID.
    pub user_id: u64,
    /// Approved credential entry ID.
    pub entry_id: String,
    /// Approved immutable credential record ID.
    pub record_id: String,
    /// Approved credential version.
    pub version: u64,
    /// Approved subscription route.
    pub route: String,
    /// Models the session may request.
    pub models: Vec<String>,
    /// Maximum admitted calls.
    pub calls: u64,
    /// Token allowance across admitted calls.
    pub tokens: u64,
    /// Repository to show the Sponsor owner.
    pub repository: String,
    /// Issue number to show the Sponsor owner.
    pub issue: u64,
}

/// JOSE header for this protocol's only supported JWS profile.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Header<'a> {
    alg: &'a str,
    typ: &'a str,
    kid: &'a str,
}

/// Sign an exchange claim using the named Ed25519 PKCS #8 private key.
pub fn sign(claim: &SessionClaim, kid: &str, private_key: &[u8]) -> Result<String> {
    ensure!(!kid.is_empty(), "empty claim key ID");
    let key = Ed25519KeyPair::from_pkcs8_maybe_unchecked(private_key)
        .map_err(|_| anyhow::anyhow!("invalid Ed25519 PKCS #8 key"))?;
    let header = Header {
        alg: "EdDSA",
        typ: "JWT",
        kid,
    };
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(claim)?)
    );
    let signature = key.sign(input.as_bytes());
    Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)))
}

/// Public exchange keys used to verify compact session claims.
pub struct VerificationKeys(HashMap<String, [u8; 32]>);

impl VerificationKeys {
    /// Build a nonempty key set from unique IDs and raw Ed25519 public keys.
    pub fn new(keys: impl IntoIterator<Item = (String, [u8; 32])>) -> Result<Self> {
        let mut by_id = HashMap::new();
        for (kid, key) in keys {
            ensure!(!kid.is_empty(), "empty claim key ID");
            ensure!(by_id.insert(kid, key).is_none(), "duplicate claim key ID");
        }
        ensure!(!by_id.is_empty(), "no exchange public keys configured");
        Ok(Self(by_id))
    }

    /// Read a JSON Web Key Set of named OKP Ed25519 public keys.
    pub fn from_jwks(json: &[u8]) -> Result<Self> {
        #[derive(Deserialize)]
        struct Jwks {
            keys: Vec<Jwk>,
        }
        #[derive(Deserialize)]
        struct Jwk {
            kid: String,
            kty: String,
            crv: String,
            x: String,
        }
        let Jwks { keys } = serde_json::from_slice(json)?;
        let keys = keys
            .into_iter()
            .map(|key| {
                ensure!(
                    key.kty == "OKP" && key.crv == "Ed25519",
                    "exchange key must be OKP Ed25519"
                );
                let bytes = URL_SAFE_NO_PAD
                    .decode(key.x)?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid Ed25519 public key length"))?;
                Ok((key.kid, bytes))
            })
            .collect::<Result<Vec<_>>>()?;
        Self::new(keys)
    }

    /// Authenticate the JWS and require the exchange issuer and current validity.
    pub fn verify(&self, compact: &str, now: i64) -> Result<SessionClaim> {
        let (input, signature) = compact.rsplit_once('.').context("invalid compact JWS")?;
        let (header, payload) = input.split_once('.').context("invalid compact JWS")?;
        let header = URL_SAFE_NO_PAD.decode(header)?;
        let header: Header = serde_json::from_slice(&header)?;
        ensure!(
            header.alg == "EdDSA" && header.typ == "JWT",
            "unexpected claim signature profile"
        );
        let key = self.0.get(header.kid).context("unknown exchange key ID")?;
        UnparsedPublicKey::new(&ED25519, key)
            .verify(input.as_bytes(), &URL_SAFE_NO_PAD.decode(signature)?)
            .map_err(|_| anyhow::anyhow!("invalid claim signature"))?;
        let claim: SessionClaim = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload)?)?;
        ensure!(claim.iss == ISSUER, "unexpected claim issuer");
        ensure!(
            !claim.jti.is_empty() && !claim.sub.is_empty(),
            "empty claim or session ID"
        );
        ensure!(claim.iat <= now && now < claim.exp, "claim is not current");
        Ok(claim)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exercise the RFC 8032 example key with an independently signed OpenSSL JWS.
    #[test]
    fn openssl_signature_and_pkcs8_interoperate() {
        let key = URL_SAFE_NO_PAD
            .decode("MC4CAQAwBQYDK2VwBCIEIJ1hsZ3v_VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g")
            .unwrap();
        let keys = VerificationKeys::from_jwks(br#"{"keys":[{"kid":"fixture","kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}"#).unwrap();
        let claim = SessionClaim {
            jti: "claim".into(),
            iss: ISSUER.into(),
            sub: "session".into(),
            iat: 100,
            exp: 200,
            relay_id: "relay".into(),
            user_id: 7,
            entry_id: "entry".into(),
            record_id: "record".into(),
            version: 1,
            route: "claude-subscription".into(),
            models: vec!["model".into()],
            calls: 2,
            tokens: 9,
            repository: "owner/repo".into(),
            issue: 1,
        };
        let compact = sign(&claim, "fixture", &key).unwrap();
        assert_eq!(
            compact.rsplit_once('.').unwrap().1,
            "XvxBaCSvTXicyzV8qmVULQFftxg8fJ4dXsooLk5kUuy6A_UdAeLlbDZym_UnFQUPdTAJNSDRWRA3OCQIsnqVDw"
        );
        assert_eq!(keys.verify(&compact, 100).unwrap(), claim);
        assert!(keys.verify(&compact, 99).is_err());
        assert!(keys.verify(&compact, 200).is_err());
    }
}
