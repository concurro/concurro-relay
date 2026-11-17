//! Connections from the relay to Concurro.

use std::{path::PathBuf, sync::Arc};

use anyhow::{Context, Result};
use rustls::{
    ClientConfig, RootCertStore,
    crypto::ring,
    pki_types::{CertificateDer, ServerName, pem::PemObject},
};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, client::TlsStream};

/// Where the relay reaches Concurro.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Server {
    /// Host and port.
    pub address: String,
    /// Certificates to trust beyond the public authorities, for a server
    /// under development.
    pub ca_file: Option<PathBuf>,
}

/// A connection to Concurro.
pub type Connection = TlsStream<TcpStream>;

impl Server {
    /// Opens a connection, authenticating the server by its certificate.
    pub async fn connect(&self) -> Result<Connection> {
        let mut roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(path) = &self.ca_file {
            for certificate in CertificateDer::pem_file_iter(path)
                .with_context(|| format!("could not read {}", path.display()))?
            {
                roots.add(certificate?)?;
            }
        }
        let config = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let host = self
            .address
            .rsplit_once(':')
            .map_or(self.address.as_str(), |(host, _)| host);
        let name = ServerName::try_from(host.to_owned())
            .with_context(|| format!("{host} is not a server name"))?;
        let stream = TcpStream::connect(&self.address)
            .await
            .with_context(|| format!("could not reach {}", self.address))?;
        stream.set_nodelay(true)?;
        TlsConnector::from(Arc::new(config))
            .connect(name, stream)
            .await
            .with_context(|| format!("could not secure the connection to {}", self.address))
    }
}
