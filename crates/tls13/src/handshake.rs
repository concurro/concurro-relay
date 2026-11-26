//! Bounded joint TLS 1.3 hello and server-flight authentication.

use std::{collections::BTreeMap, io::Cursor, sync::Arc};

use anyhow::{Context, Result, anyhow, bail, ensure};
use p256::PublicKey;
use ring::{
    digest, hmac,
    rand::{SecureRandom, SystemRandom},
};
use rustls::{
    RootCertStore,
    client::{WebPkiServerVerifier, danger::ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use webpki::{
    EndEntityCert,
    ring::{ECDSA_P256_SHA256, RSA_PSS_2048_8192_SHA256_LEGACY_KEY},
};

use crate::record::{Epoch, expand};

const HELLO_RETRY_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// Supported provider ALPN profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Profile {
    /// Codex offers no ALPN extension and uses HTTP/1.1/WebSocket.
    Codex,
    /// The shared HTTP/2 transport offers and requires `h2` ALPN.
    TlsKeyUpdate,
}

/// Public ClientHello bytes and their echoed legacy session identifier.
pub struct ClientHello {
    /// Exact handshake bytes for the transcript and provider write.
    pub wire: Vec<u8>,
    /// Thirty-two-byte session identifier required in ServerHello.
    pub session: [u8; 32],
}

/// Read a fixed-width TLS field from an exact message body.
fn take<'a>(data: &'a [u8], offset: &mut usize, length: usize) -> Result<&'a [u8]> {
    let end = offset
        .checked_add(length)
        .context("TLS field offset overflow")?;
    ensure!(end <= data.len(), "truncated TLS field");
    let part = &data[*offset..end];
    *offset = end;
    Ok(part)
}

/// Read a one-, two-, or three-byte length-prefixed TLS vector.
fn vector<'a>(data: &'a [u8], offset: &mut usize, width: usize) -> Result<&'a [u8]> {
    let length = take(data, offset, width)?
        .iter()
        .fold(0usize, |n, byte| (n << 8) | *byte as usize);
    take(data, offset, length)
}

/// Encode a bounded TLS vector.
fn packed(data: &[u8], width: usize) -> Result<Vec<u8>> {
    ensure!(
        matches!(width, 1..=3) && data.len() < (1usize << (width * 8)),
        "TLS vector is too long"
    );
    let length = (data.len() as u32).to_be_bytes();
    Ok([&length[4 - width..], data].concat())
}

/// Encode one TLS extension.
fn extension(kind: u16, data: &[u8]) -> Result<Vec<u8>> {
    Ok([kind.to_be_bytes().as_slice(), &packed(data, 2)?].concat())
}

/// Encode one TLS handshake message.
pub fn handshake_message(kind: u8, body: &[u8]) -> Result<Vec<u8>> {
    Ok([&[kind][..], packed(body, 3)?.as_slice()].concat())
}

/// Encode one plaintext TLS record.
pub fn plaintext_record(kind: u8, body: &[u8]) -> Result<Vec<u8>> {
    Ok([&[kind, 3, 3][..], packed(body, 2)?.as_slice()].concat())
}

/// Parse extensions and reject duplicate identifiers.
fn extensions(data: &[u8]) -> Result<BTreeMap<u16, Vec<u8>>> {
    let mut found = BTreeMap::new();
    let mut offset = 0;
    while offset < data.len() {
        let kind = u16::from_be_bytes(take(data, &mut offset, 2)?.try_into().unwrap());
        let value = vector(data, &mut offset, 2)?.to_vec();
        ensure!(
            found.insert(kind, value).is_none(),
            "duplicate TLS extension"
        );
    }
    Ok(found)
}

/// Encode the existing single-suite, P-256 joint ClientHello from supplied randomness.
pub fn client_hello_with_random(
    profile: Profile,
    hostname: &str,
    joint_point: &[u8],
    random: [u8; 32],
    session: [u8; 32],
) -> Result<ClientHello> {
    ensure!(hostname.is_ascii(), "TLS hostname must be ASCII");
    ensure!(
        joint_point.len() == 65 && joint_point[0] == 4,
        "invalid joint public key encoding"
    );
    let name = packed(hostname.as_bytes(), 2)?;
    let server_name = packed(&[&[0], name.as_slice()].concat(), 2)?;
    let groups = packed(&[0, 0x17], 2)?;
    let signatures = packed(&[4, 3, 8, 4, 8, 5, 8, 6, 5, 3, 6, 3], 2)?;
    let key_share = packed(
        &[&[0, 0x17], packed(joint_point, 2)?.as_slice()].concat(),
        2,
    )?;
    let mut ext = Vec::new();
    for (kind, value) in [(0, server_name), (10, groups), (13, signatures)] {
        ext.extend(extension(kind, &value)?);
    }
    if profile == Profile::TlsKeyUpdate {
        ext.extend(extension(16, &packed(&packed(b"h2", 1)?, 2)?)?);
    }
    ext.extend(extension(43, &[2, 3, 4])?);
    ext.extend(extension(51, &key_share)?);
    let mut body = Vec::new();
    body.extend([3, 3]);
    body.extend(random);
    body.extend(packed(&session, 1)?);
    body.extend(packed(&[0x13, 1], 2)?);
    body.extend([1, 0]);
    body.extend(packed(&ext, 2)?);
    Ok(ClientHello {
        wire: handshake_message(1, &body)?,
        session,
    })
}

/// Generate a fresh joint ClientHello with the requested ALPN profile.
pub fn client_hello(profile: Profile, hostname: &str, joint_point: &[u8]) -> Result<ClientHello> {
    let random = SystemRandom::new();
    let mut hello_random = [0; 32];
    let mut session = [0; 32];
    random
        .fill(&mut hello_random)
        .map_err(|_| anyhow!("TLS random generation failed"))?;
    random
        .fill(&mut session)
        .map_err(|_| anyhow!("TLS random generation failed"))?;
    client_hello_with_random(profile, hostname, joint_point, hello_random, session)
}

/// Bind an exact ClientHello to the agreed host, point, and ALPN profile.
pub fn validate_client_hello(
    profile: Profile,
    message: &[u8],
    hostname: &str,
    joint_point: &[u8],
) -> Result<[u8; 32]> {
    let body = handshake_body(message, 1)?;
    let mut offset = 0;
    let legacy = take(body, &mut offset, 2)?;
    take(body, &mut offset, 32)?;
    let session = vector(body, &mut offset, 1)?;
    let suites = vector(body, &mut offset, 2)?;
    let compression = vector(body, &mut offset, 1)?;
    let ext_raw = vector(body, &mut offset, 2)?;
    ensure!(
        offset == body.len()
            && legacy == [3, 3]
            && session.len() == 32
            && suites == [0x13, 1]
            && compression == [0],
        "ClientHello profile mismatch"
    );
    let ext = extensions(ext_raw)?;
    let expected: &[u16] = if profile == Profile::TlsKeyUpdate {
        &[0, 10, 13, 16, 43, 51]
    } else {
        &[0, 10, 13, 43, 51]
    };
    ensure!(
        ext.keys().copied().collect::<Vec<_>>() == expected,
        "ClientHello extensions mismatch"
    );
    let mut name_offset = 0;
    let name_list = vector(&ext[&0], &mut name_offset, 2)?;
    let mut host_offset = 0;
    ensure!(
        take(name_list, &mut host_offset, 1)? == [0],
        "ClientHello name type mismatch"
    );
    let name = vector(name_list, &mut host_offset, 2)?;
    ensure!(
        name_offset == ext[&0].len()
            && host_offset == name_list.len()
            && name == hostname.as_bytes(),
        "ClientHello hostname mismatch"
    );
    ensure!(
        ext[&10] == packed(&[0, 0x17], 2)? && ext[&43] == [2, 3, 4],
        "ClientHello public binding mismatch"
    );
    let key_share = packed(
        &[&[0, 0x17], packed(joint_point, 2)?.as_slice()].concat(),
        2,
    )?;
    ensure!(ext[&51] == key_share, "ClientHello joint point mismatch");
    if profile == Profile::TlsKeyUpdate {
        ensure!(
            ext[&16] == packed(&packed(b"h2", 1)?, 2)?,
            "ClientHello ALPN mismatch"
        );
    }
    let mut signature_offset = 0;
    let algorithms = vector(&ext[&13], &mut signature_offset, 2)?;
    ensure!(
        signature_offset == ext[&13].len() && algorithms.windows(2).any(|scheme| scheme == [4, 3]),
        "ClientHello signature algorithms mismatch"
    );
    Ok(session.try_into().unwrap())
}

/// Decode an exact TLS handshake message of the expected type.
fn handshake_body(message: &[u8], kind: u8) -> Result<&[u8]> {
    ensure!(
        message.len() >= 4 && message[0] == kind,
        "unexpected TLS handshake message"
    );
    let size = u32::from_be_bytes([0, message[1], message[2], message[3]]) as usize;
    ensure!(
        size + 4 == message.len(),
        "incomplete TLS handshake message"
    );
    Ok(&message[4..])
}

/// Validate the selected server profile and return its P-256 share.
pub fn server_hello(message: &[u8], session: &[u8; 32]) -> Result<[u8; 65]> {
    let body = handshake_body(message, 2)?;
    let mut offset = 0;
    let legacy = take(body, &mut offset, 2)?;
    let random = take(body, &mut offset, 32)?;
    let echoed = vector(body, &mut offset, 1)?;
    let suite = take(body, &mut offset, 2)?;
    let compression = take(body, &mut offset, 1)?;
    let ext_raw = vector(body, &mut offset, 2)?;
    ensure!(
        offset == body.len()
            && legacy == [3, 3]
            && random != HELLO_RETRY_RANDOM
            && echoed == session
            && suite == [0x13, 1]
            && compression == [0],
        "ServerHello profile mismatch or HelloRetryRequest"
    );
    let ext = extensions(ext_raw)?;
    ensure!(
        ext.len() == 2
            && ext.get(&43).is_some_and(|value| value.as_slice() == [3, 4])
            && ext.contains_key(&51),
        "ServerHello extension mismatch"
    );
    let mut key_offset = 0;
    ensure!(
        take(&ext[&51], &mut key_offset, 2)? == [0, 0x17],
        "ServerHello group mismatch"
    );
    let point = vector(&ext[&51], &mut key_offset, 2)?;
    ensure!(
        key_offset == ext[&51].len() && point.len() == 65 && point[0] == 4,
        "invalid server P-256 point"
    );
    PublicKey::from_sec1_bytes(point).context("invalid server P-256 point")?;
    Ok(point.try_into().unwrap())
}

/// Decode an exact plaintext TLS record with the Python reference length cap.
pub fn parse_plaintext_record(wire: &[u8]) -> Result<(u8, &[u8])> {
    ensure!(
        wire.len() >= 5 && wire[1..3] == [3, 3],
        "invalid TLS record header"
    );
    let length = u16::from_be_bytes([wire[3], wire[4]]) as usize;
    ensure!(
        length <= 16_640 && wire.len() == length + 5,
        "invalid TLS record length"
    );
    Ok((wire[0], &wire[5..]))
}

/// Decode a TLS 1.3 Certificate body into the leaf and intermediates.
fn certificate_chain(body: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let mut offset = 0;
    let context = vector(body, &mut offset, 1)?;
    let entries = vector(body, &mut offset, 3)?;
    ensure!(
        context.is_empty() && offset == body.len(),
        "unexpected certificate context"
    );
    let mut certificates = Vec::new();
    let mut index = 0;
    while index < entries.len() {
        let cert = vector(entries, &mut index, 3)?;
        vector(entries, &mut index, 2)?;
        certificates.push(CertificateDer::from(cert.to_vec()));
    }
    ensure!(!certificates.is_empty(), "empty certificate chain");
    Ok(certificates)
}

/// Authenticate the signed server transcript with its verified leaf key.
fn verify_signature(body: &[u8], leaf: &CertificateDer<'_>, transcript: &[u8]) -> Result<()> {
    let mut offset = 0;
    let scheme = u16::from_be_bytes(take(body, &mut offset, 2)?.try_into().unwrap());
    let signature = vector(body, &mut offset, 2)?;
    ensure!(offset == body.len(), "trailing CertificateVerify bytes");
    let algorithm = match scheme {
        0x0403 => ECDSA_P256_SHA256,
        0x0804 => RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        _ => bail!("unsupported certificate signature scheme {scheme:#x}"),
    };
    let mut signed = vec![b' '; 64];
    signed.extend(b"TLS 1.3, server CertificateVerify\0");
    signed.extend(digest::digest(&digest::SHA256, transcript).as_ref());
    EndEntityCert::try_from(leaf)
        .context("invalid server leaf certificate")?
        .verify_signature(algorithm, &signed, signature)
        .context("invalid TLS CertificateVerify signature")
}

/// Authentication state for the encrypted server flight through Finished.
pub struct ServerFlight {
    /// Exact public and authenticated handshake bytes.
    transcript: Vec<u8>,
    /// Server handshake traffic epoch.
    epoch: Epoch,
    /// Expected provider identity, independent of TCP destination.
    hostname: String,
    /// Configured CA trust roots.
    verifier: Arc<WebPkiServerVerifier>,
    /// Handshake bytes split across encrypted records.
    buffer: Vec<u8>,
    /// Next expected handshake message index.
    stage: usize,
    /// Verified server leaf for CertificateVerify.
    leaf: Option<CertificateDer<'static>>,
    /// Selected route ALPN profile.
    profile: Profile,
}

impl ServerFlight {
    /// Validate the public hellos and configured CA before accepting server records.
    pub fn new(
        profile: Profile,
        client: &[u8],
        server: &[u8],
        joint_point: &[u8],
        server_secret: [u8; 32],
        ca_pem: &[u8],
        hostname: &str,
    ) -> Result<Self> {
        let session = validate_client_hello(profile, client, hostname, joint_point)?;
        server_hello(server, &session)?;
        let mut roots = RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut Cursor::new(ca_pem)) {
            roots.add(cert?).context("invalid TLS CA certificate")?;
        }
        let verifier = WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .context("empty TLS CA store")?;
        Ok(Self {
            transcript: [client, server].concat(),
            epoch: Epoch::new(server_secret)?,
            hostname: hostname.to_owned(),
            verifier,
            buffer: Vec::new(),
            stage: 0,
            leaf: None,
            profile,
        })
    }

    /// Authenticate a provider-origin record and report verified Finished.
    pub fn feed(&mut self, wire: &[u8]) -> Result<bool> {
        ensure!(self.stage < 4, "server flight already finished");
        if wire == [20, 3, 3, 0, 1, 1] {
            return Ok(false);
        }
        ensure!(
            wire.first() == Some(&23),
            "unexpected server handshake record"
        );
        let (kind, plaintext) = self.epoch.decrypt(wire)?;
        ensure!(
            kind == 22,
            "server sent non-handshake content before Finished"
        );
        self.buffer.extend(plaintext);
        let expected = [8, 11, 15, 20];
        while self.buffer.len() >= 4 {
            let size = u32::from_be_bytes([0, self.buffer[1], self.buffer[2], self.buffer[3]])
                as usize
                + 4;
            if self.buffer.len() < size {
                break;
            }
            let message: Vec<_> = self.buffer.drain(..size).collect();
            ensure!(
                self.stage < 4 && message[0] == expected[self.stage],
                "unexpected server handshake message order"
            );
            let body = &message[4..];
            match self.stage {
                0 => self.encrypted_extensions(body)?,
                1 => {
                    let chain = certificate_chain(body)?;
                    let host = ServerName::try_from(self.hostname.clone())
                        .context("invalid provider hostname")?;
                    self.verifier
                        .verify_server_cert(&chain[0], &chain[1..], &host, &[], UnixTime::now())
                        .context("server certificate rejected")?;
                    self.leaf = Some(chain[0].clone());
                }
                2 => verify_signature(
                    body,
                    self.leaf.as_ref().context("server certificate missing")?,
                    &self.transcript,
                )?,
                _ => {
                    ensure!(body.len() == 32, "wrong Finished length");
                    let key = expand::<32>(self.epoch.secret(), b"finished")?;
                    hmac::verify(
                        &hmac::Key::new(hmac::HMAC_SHA256, &key),
                        digest::digest(&digest::SHA256, &self.transcript).as_ref(),
                        body,
                    )
                    .map_err(|_| anyhow!("server Finished mismatch"))?;
                }
            }
            self.transcript.extend(&message);
            self.stage += 1;
        }
        ensure!(
            self.stage != 4 || self.buffer.is_empty(),
            "extra handshake bytes after Finished"
        );
        Ok(self.stage == 4)
    }

    /// Produce the client Finished record after the server flight verifies.
    pub fn client_finished(&self, client_secret: [u8; 32]) -> Result<(Vec<u8>, [u8; 32])> {
        ensure!(self.stage == 4, "server Finished was not verified");
        let h3: [u8; 32] = digest::digest(&digest::SHA256, &self.transcript)
            .as_ref()
            .try_into()
            .unwrap();
        let key = expand::<32>(&client_secret, b"finished")?;
        let finished = handshake_message(
            20,
            hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &key), &h3).as_ref(),
        )?;
        Ok((Epoch::new(client_secret)?.encrypt(&finished, 22)?, h3))
    }

    /// Check the limited EncryptedExtensions supported by the selected route.
    fn encrypted_extensions(&self, body: &[u8]) -> Result<()> {
        let mut offset = 0;
        let mut ext = extensions(vector(body, &mut offset, 2)?)?;
        ensure!(offset == body.len(), "trailing EncryptedExtensions bytes");
        if let Some(groups) = ext.remove(&10) {
            let mut group_offset = 0;
            let values = vector(&groups, &mut group_offset, 2)?;
            ensure!(
                group_offset == groups.len()
                    && values.len() % 2 == 0
                    && values.as_chunks::<2>().0.contains(&[0, 0x17]),
                "invalid EncryptedExtensions supported groups"
            );
        }
        if self.profile == Profile::TlsKeyUpdate {
            ensure!(
                ext.remove(&16).as_deref() == Some(packed(&packed(b"h2", 1)?, 2)?.as_slice()),
                "server did not select h2 ALPN"
            );
        }
        ensure!(
            ext.is_empty() || ext.len() == 1 && ext.get(&0).is_some_and(Vec::is_empty),
            "unexpected EncryptedExtensions"
        );
        Ok(())
    }
}
