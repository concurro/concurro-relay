//! The key pair by which a verifier recognizes a registered relay.

use anyhow::{Result, anyhow};
use ring::{
    rand::{SecureRandom, SystemRandom},
    signature::{self, Ed25519KeyPair, KeyPair, UnparsedPublicKey},
};

/// A relay's key pair.
pub struct Identity(Ed25519KeyPair);

impl Identity {
    /// A new key pair, with its private key as PKCS #8 for storing.
    pub fn generate() -> Result<(Self, Vec<u8>)> {
        let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|_| anyhow!("could not generate a key"))?;
        Ok((
            Self::from_pkcs8(document.as_ref())?,
            document.as_ref().to_vec(),
        ))
    }

    pub fn from_pkcs8(private_key: &[u8]) -> Result<Self> {
        Ed25519KeyPair::from_pkcs8(private_key)
            .map(Self)
            .map_err(|_| anyhow!("relay key is not a valid Ed25519 private key"))
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.0.public_key().as_ref().to_vec()
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.0.sign(message).as_ref().to_vec()
    }
}

/// Whether `signature` is `public_key`'s signature of `message`.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    UnparsedPublicKey::new(&signature::ED25519, public_key)
        .verify(message, signature)
        .is_ok()
}

/// Random bytes for a challenge or a code.
pub fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    SystemRandom::new()
        .fill(&mut bytes)
        .expect("the system provides randomness");
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_verifies_only_for_its_key_and_message() {
        let (identity, stored) = Identity::generate().unwrap();
        let signature = identity.sign(b"message");
        assert!(verify(&identity.public_key(), b"message", &signature));
        assert!(!verify(&identity.public_key(), b"another", &signature));
        assert!(!verify(
            &Identity::generate().unwrap().0.public_key(),
            b"message",
            &signature
        ));
        assert_eq!(
            Identity::from_pkcs8(&stored).unwrap().public_key(),
            identity.public_key()
        );
    }
}
