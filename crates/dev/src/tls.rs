//! A certificate for a verifier under development.

use std::sync::Arc;

use anyhow::Result;
use rustls::{
    ServerConfig,
    crypto::ring,
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
};
use tokio_rustls::TlsAcceptor;

/// An acceptor with a new self-signed certificate for `names`, and that
/// certificate as PEM for relays to trust.
pub fn self_signed(names: Vec<String>) -> Result<(TlsAcceptor, String)> {
    let certified = rcgen::generate_simple_self_signed(names)?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));
    let config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(vec![certified.cert.der().clone()], key)?;
    Ok((TlsAcceptor::from(Arc::new(config)), certified.cert.pem()))
}
