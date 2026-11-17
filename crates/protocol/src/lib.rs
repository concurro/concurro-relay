//! What a Concurro relay and the verifier it proves to have in common: the
//! messages they exchange, the request encoding both derive, and how a relay
//! identifies itself.

pub mod identity;
pub mod link;
pub mod meter;
pub mod route;
pub mod timing;
pub mod wire;
pub mod ws;

use tlsn::webpki::{CertificateDer, RootCertStore};
use tlsn_server_fixture_certs::CA_CERT_DER;

/// Authenticated DNS name of the local TLSNotary provider fixture.
pub use tlsn_server_fixture_certs::SERVER_DOMAIN as FIXTURE_PROVIDER_HOST;

/// Trust anchors used to authenticate the provider.
#[derive(Clone, Copy, Debug)]
pub enum Roots {
    /// The TLSNotary fixture CA that signs a mock provider's certificate.
    Fixture,
    /// Mozilla's root program, for real providers.
    Mozilla,
}

impl Roots {
    pub fn store(self) -> RootCertStore {
        match self {
            Self::Fixture => RootCertStore {
                roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
            },
            Self::Mozilla => RootCertStore::mozilla(),
        }
    }
}
