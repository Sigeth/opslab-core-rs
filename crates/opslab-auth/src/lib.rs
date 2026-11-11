//! Short-lived access tokens.
//!
//! The api mints a token when a student opens a terminal, a web endpoint or the
//! IDE of an instance; the gateway verifies it before connecting. Tokens are
//! EdDSA (Ed25519) JWTs. The api publishes its public keys as a JWKS document,
//! so the gateway never needs the private key nor a database.
//!
//! ```
//! use std::time::{Duration, SystemTime};
//! use opslab_auth::{AccessGrant, AccessKind, Signer, Verifier};
//!
//! let signer = Signer::generate()?;
//! let grant = AccessGrant {
//!     user_id: "42".into(),
//!     instance: "opslab-instances/hello-shell-alice".into(),
//!     machine: "box".into(),
//!     kind: AccessKind::Terminal { user: "student".into() },
//! };
//! let token = signer.sign(&grant, SystemTime::now(), Duration::from_secs(120))?;
//!
//! let verifier = Verifier::from_jwks(&signer.jwks())?;
//! let claims = verifier.verify(&token)?;
//! assert_eq!(claims.grant, grant);
//! # Ok::<(), opslab_auth::Error>(())
//! ```

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey, KeypairBytes};
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

/// The JWKS document type, re-exported so consumers do not need to depend on
/// (and keep in sync with) the same jsonwebtoken version.
pub use jsonwebtoken::jwk::JwkSet;

/// Issuer of every access token.
pub const ISSUER: &str = "opslab-api";
/// Audience of tokens accepted by the gateway.
pub const AUDIENCE_GATEWAY: &str = "opslab-gateway";
/// Recommended lifetime: just long enough to open a connection.
pub const DEFAULT_TTL: Duration = Duration::from_secs(120);
/// Clock skew tolerated when verifying, in seconds.
const LEEWAY_SECS: u64 = 5;

/// Errors of this crate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid signing key: {0}")]
    Key(String),
    #[error("system clock is before 1970")]
    Clock,
    #[error("token has no key ID")]
    MissingKeyId,
    #[error("unknown key ID {0:?}")]
    UnknownKeyId(String),
    #[error(transparent)]
    Jwt(#[from] jsonwebtoken::errors::Error),
}

/// What an access token grants: one user, one machine of one instance, one
/// kind of access.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessGrant {
    /// Platform user ID.
    #[serde(rename = "sub")]
    pub user_id: String,
    /// The ChallengeInstance, as "namespace/name".
    pub instance: String,
    /// Machine name inside the instance.
    pub machine: String,
    /// Kind of access.
    #[serde(flatten)]
    pub kind: AccessKind,
}

/// Kind of access granted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "access", rename_all = "lowercase")]
pub enum AccessKind {
    /// An interactive shell as a Unix user of the machine.
    Terminal { user: String },
    /// An HTTP endpoint on a port of the machine.
    Web { port: u16 },
    /// The browser IDE running on the machine.
    Ide,
}

/// Verified claims of an access token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessClaims {
    pub iss: String,
    pub aud: String,
    /// Expiry (seconds since the Unix epoch).
    pub exp: u64,
    /// Issued at (seconds since the Unix epoch).
    pub iat: u64,
    /// Unique token ID, for audit logs.
    pub jti: String,
    #[serde(flatten)]
    pub grant: AccessGrant,
}

/// Mints access tokens. Lives in the api.
pub struct Signer {
    key_id: String,
    signing_key: SigningKey,
    encoding_key: EncodingKey,
}

impl Signer {
    /// Generates a new random key.
    pub fn generate() -> Result<Self, Error> {
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret).map_err(|e| Error::Key(e.to_string()))?;
        Self::from_signing_key(SigningKey::from_bytes(&secret))
    }

    /// Loads a key from a PKCS#8 PEM document (e.g. a Kubernetes Secret).
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, Error> {
        let key = SigningKey::from_pkcs8_pem(pem).map_err(|e| Error::Key(e.to_string()))?;
        Self::from_signing_key(key)
    }

    /// Serializes the key as a PKCS#8 PEM document, to persist it.
    pub fn to_pkcs8_pem(&self) -> Result<String, Error> {
        let pem = self
            .signing_key
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| Error::Key(e.to_string()))?;
        Ok(pem.to_string())
    }

    fn from_signing_key(signing_key: SigningKey) -> Result<Self, Error> {
        // PKCS#8 v1 (private key only): the form jsonwebtoken expects for EdDSA.
        let der = KeypairBytes {
            secret_key: signing_key.to_bytes(),
            public_key: None,
        }
        .to_pkcs8_der()
        .map_err(|e| Error::Key(e.to_string()))?;
        let encoding_key = EncodingKey::from_ed_der(der.as_bytes());
        Ok(Self {
            // Derived from the public key: stable across restarts, unique per key.
            key_id: key_id(signing_key.verifying_key().as_bytes()),
            signing_key,
            encoding_key,
        })
    }

    /// ID of the key, set in the `kid` header of every token.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Mints a token for `grant`, valid for `ttl` from `now`.
    pub fn sign(
        &self,
        grant: &AccessGrant,
        now: SystemTime,
        ttl: Duration,
    ) -> Result<String, Error> {
        let iat = now
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Clock)?
            .as_secs();
        let claims = AccessClaims {
            iss: ISSUER.into(),
            aud: AUDIENCE_GATEWAY.into(),
            exp: iat + ttl.as_secs(),
            iat,
            jti: uuid::Uuid::new_v4().to_string(),
            grant: grant.clone(),
        };
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.key_id.clone());
        Ok(jsonwebtoken::encode(&header, &claims, &self.encoding_key)?)
    }

    /// The public key as a JWKS document, served by the api to the gateway.
    pub fn jwks(&self) -> JwkSet {
        let mut jwk = Jwk::from_encoding_key(&self.encoding_key, Algorithm::EdDSA)
            .expect("an Ed25519 encoding key always converts to a JWK");
        jwk.common.key_id = Some(self.key_id.clone());
        JwkSet { keys: vec![jwk] }
    }
}

/// Verifies access tokens. Lives in the gateway.
pub struct Verifier {
    keys: HashMap<String, DecodingKey>,
    validation: Validation,
}

impl Verifier {
    /// Builds a verifier trusting every Ed25519 key of a JWKS document. Keys
    /// without a `kid` are ignored.
    pub fn from_jwks(jwks: &JwkSet) -> Result<Self, Error> {
        let mut keys = HashMap::new();
        for jwk in &jwks.keys {
            if let Some(kid) = &jwk.common.key_id {
                keys.insert(kid.clone(), DecodingKey::from_jwk(jwk)?);
            }
        }
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[ISSUER]);
        validation.set_audience(&[AUDIENCE_GATEWAY]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.leeway = LEEWAY_SECS;
        Ok(Self { keys, validation })
    }

    /// Verifies signature, issuer, audience and expiry, and returns the claims.
    pub fn verify(&self, token: &str) -> Result<AccessClaims, Error> {
        let kid = jsonwebtoken::decode_header(token)?
            .kid
            .ok_or(Error::MissingKeyId)?;
        let key = self.keys.get(&kid).ok_or(Error::UnknownKeyId(kid))?;
        Ok(jsonwebtoken::decode::<AccessClaims>(token, key, &self.validation)?.claims)
    }
}

/// First 8 bytes of the public key, hex-encoded.
fn key_id(public_key: &[u8; 32]) -> String {
    public_key[..8].iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant() -> AccessGrant {
        AccessGrant {
            user_id: "42".into(),
            instance: "opslab-instances/ssh-alice".into(),
            machine: "server".into(),
            kind: AccessKind::Web { port: 8080 },
        }
    }

    fn token(signer: &Signer, issued_secs_ago: u64, ttl_secs: u64) -> String {
        let now = SystemTime::now() - Duration::from_secs(issued_secs_ago);
        signer
            .sign(&grant(), now, Duration::from_secs(ttl_secs))
            .unwrap()
    }

    #[test]
    fn round_trip() {
        let signer = Signer::generate().unwrap();
        let verifier = Verifier::from_jwks(&signer.jwks()).unwrap();
        let claims = verifier.verify(&token(&signer, 0, 60)).unwrap();
        assert_eq!(claims.grant, grant());
        assert_eq!(claims.aud, AUDIENCE_GATEWAY);
    }

    #[test]
    fn claims_wire_format() {
        let json = serde_json::to_value(grant()).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"sub": "42", "instance": "opslab-instances/ssh-alice", "machine": "server", "access": "web", "port": 8080})
        );
    }

    #[test]
    fn rejects_expired_tokens() {
        let signer = Signer::generate().unwrap();
        let verifier = Verifier::from_jwks(&signer.jwks()).unwrap();
        assert!(verifier.verify(&token(&signer, 600, 60)).is_err());
    }

    #[test]
    fn rejects_tokens_from_other_keys() {
        let signer = Signer::generate().unwrap();
        let other = Signer::generate().unwrap();
        let verifier = Verifier::from_jwks(&signer.jwks()).unwrap();
        assert!(matches!(
            verifier.verify(&token(&other, 0, 60)),
            Err(Error::UnknownKeyId(_))
        ));
    }

    #[test]
    fn rejects_tampered_tokens() {
        let signer = Signer::generate().unwrap();
        let verifier = Verifier::from_jwks(&signer.jwks()).unwrap();
        let original = token(&signer, 0, 60);
        let longer = token(&signer, 0, 3600);
        // Claims of the long-lived token with the signature of the short one.
        let (claims, _) = longer.rsplit_once('.').unwrap();
        let (_, signature) = original.rsplit_once('.').unwrap();
        let forged = format!("{claims}.{signature}");
        assert!(verifier.verify(&forged).is_err());
    }

    #[test]
    fn rejects_other_algorithms() {
        // Algorithm confusion: a valid kid but an HMAC signature.
        let signer = Signer::generate().unwrap();
        let verifier = Verifier::from_jwks(&signer.jwks()).unwrap();
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(signer.key_id().to_string());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = AccessClaims {
            iss: ISSUER.into(),
            aud: AUDIENCE_GATEWAY.into(),
            exp: now + 60,
            iat: now,
            jti: "x".into(),
            grant: grant(),
        };
        let forged =
            jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(b"guess")).unwrap();
        assert!(verifier.verify(&forged).is_err());
    }

    #[test]
    fn pem_round_trip_keeps_key_id() {
        let signer = Signer::generate().unwrap();
        let reloaded = Signer::from_pkcs8_pem(&signer.to_pkcs8_pem().unwrap()).unwrap();
        assert_eq!(signer.key_id(), reloaded.key_id());
        let verifier = Verifier::from_jwks(&signer.jwks()).unwrap();
        assert!(verifier.verify(&token(&reloaded, 0, 60)).is_ok());
    }
}
