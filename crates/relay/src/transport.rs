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
        let name = server_name(&self.address)?;
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

/// The TLS name of `address`, a `host:port` whose host may be a bracketed IPv6 address.
fn server_name(address: &str) -> Result<ServerName<'static>> {
    let host = address.rsplit_once(':').map_or(address, |(host, _)| host);
    let host = host
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host);
    ServerName::try_from(host.to_owned()).with_context(|| format!("{host} is not a server name"))
}

#[cfg(test)]
mod tests {
    use std::assert_matches;

    use super::*;

    /// DNS names, IPv4 and bracketed IPv6 addresses all name the server.
    #[test]
    fn server_names_accept_dns_and_ip_hosts() {
        assert_matches!(
            server_name("relay.example.com:7443").unwrap(),
            ServerName::DnsName(_)
        );
        assert_matches!(
            server_name("192.0.2.1:7443").unwrap(),
            ServerName::IpAddress(_)
        );
        assert_matches!(
            server_name("[2001:db8::1]:7443").unwrap(),
            ServerName::IpAddress(_)
        );
        assert!(server_name("bad host:7443").is_err());
    }
}
