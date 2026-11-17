//! TLS 1.3 AES-128-GCM traffic epochs and post-handshake records.

use anyhow::{Result, anyhow, bail, ensure};
use ring::{aead, hmac};

const MAX_RECORD_BODY: usize = 16_640;

/// Expand one SHA-256 HKDF TLS 1.3 label from a 32-byte traffic secret.
pub fn expand<const N: usize>(secret: &[u8; 32], label: &[u8]) -> Result<[u8; N]> {
    ensure!(N <= 32, "TLS label output exceeds one SHA-256 block");
    let name = [b"tls13 ".as_slice(), label].concat();
    ensure!(name.len() <= u8::MAX as usize, "TLS label is too long");
    let mut info = Vec::with_capacity(5 + name.len());
    info.extend_from_slice(&(N as u16).to_be_bytes());
    info.push(name.len() as u8);
    info.extend_from_slice(&name);
    info.push(0);
    info.push(1);
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let digest = hmac::sign(&key, &info);
    Ok(digest.as_ref()[..N].try_into().unwrap())
}

/// One directional traffic secret and implicit TLS record sequence.
pub struct Epoch {
    /// Secret used for KeyUpdate and record key derivation.
    secret: [u8; 32],
    /// Authenticated encryption key for this epoch.
    key: aead::LessSafeKey,
    /// Base nonce XORed with the record sequence.
    iv: [u8; 12],
    /// Next record sequence number.
    sequence: u64,
}

impl Epoch {
    /// Derive an AES-128-GCM key and IV at sequence zero.
    pub fn new(secret: [u8; 32]) -> Result<Self> {
        let key_bytes = expand::<16>(&secret, b"key")?;
        let unbound = aead::UnboundKey::new(&aead::AES_128_GCM, &key_bytes)
            .map_err(|_| anyhow!("invalid TLS record key"))?;
        Ok(Self {
            secret,
            key: aead::LessSafeKey::new(unbound),
            iv: expand::<12>(&secret, b"iv")?,
            sequence: 0,
        })
    }

    /// Return the next record number without exposing the secret.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Return the current traffic secret for a helper's public commitment.
    pub fn secret(&self) -> &[u8; 32] {
        &self.secret
    }

    /// Consume a record sequence and derive its twelve-byte XOR nonce.
    fn nonce(&mut self) -> Result<aead::Nonce> {
        let sequence = self.sequence;
        self.sequence = sequence
            .checked_add(1)
            .ok_or_else(|| anyhow!("TLS record sequence exhausted"))?;
        let mut nonce = self.iv;
        for (index, byte) in sequence.to_be_bytes().iter().enumerate() {
            nonce[index + 4] ^= byte;
        }
        Ok(aead::Nonce::assume_unique_for_key(nonce))
    }

    /// Encrypt one unpadded TLSInnerPlaintext with the given inner content type.
    pub fn encrypt(&mut self, content: &[u8], kind: u8) -> Result<Vec<u8>> {
        let length = content
            .len()
            .checked_add(17)
            .ok_or_else(|| anyhow!("TLS record is too large"))?;
        ensure!(length <= u16::MAX as usize, "TLS record is too large");
        let mut header = [23, 3, 3, 0, 0];
        header[3..5].copy_from_slice(&(length as u16).to_be_bytes());
        let mut inner = Vec::with_capacity(length);
        inner.extend_from_slice(content);
        inner.push(kind);
        let nonce = self.nonce()?;
        self.key
            .seal_in_place_append_tag(nonce, aead::Aad::from(header), &mut inner)
            .map_err(|_| anyhow!("TLS record encryption failed"))?;
        Ok([header.as_slice(), &inner].concat())
    }

    /// Authenticate one exact TLS record and strip its inner zero padding.
    pub fn decrypt(&mut self, wire: &[u8]) -> Result<(u8, Vec<u8>)> {
        ensure!(wire.len() >= 5, "truncated TLS record header");
        ensure!(wire[..3] == [23, 3, 3], "unexpected TLS record header");
        let length = u16::from_be_bytes([wire[3], wire[4]]) as usize;
        ensure!(length <= MAX_RECORD_BODY, "TLS record body is too large");
        ensure!(wire.len() == length + 5, "TLS record length mismatch");
        let mut body = wire[5..].to_vec();
        let nonce = self.nonce()?;
        let inner = self
            .key
            .open_in_place(nonce, aead::Aad::from(&wire[..5]), &mut body)
            .map_err(|_| anyhow!("TLS record authentication failed"))?;
        let last = inner
            .iter()
            .rposition(|byte| *byte != 0)
            .ok_or_else(|| anyhow!("TLS record lacks inner content type"))?;
        Ok((inner[last], inner[..last].to_vec()))
    }

    /// Derive the next traffic secret and reset its sequence to zero.
    pub fn updated(&self) -> Result<Self> {
        Self::new(expand::<32>(&self.secret, b"traffic upd")?)
    }
}

/// Application record decoder with ticket and server KeyUpdate state.
pub struct ApplicationRecords {
    /// Incoming server traffic epoch.
    read: Epoch,
    /// Outgoing client traffic epoch.
    write: Epoch,
    /// Fragmented post-handshake messages.
    handshake: Vec<u8>,
    /// Number of authenticated NewSessionTicket messages.
    tickets: usize,
    /// Number of authenticated server KeyUpdates.
    server_updates: usize,
}

impl ApplicationRecords {
    /// Begin independent server-read and client-write traffic epochs.
    pub fn new(server_secret: [u8; 32], client_secret: [u8; 32]) -> Result<Self> {
        Ok(Self {
            read: Epoch::new(server_secret)?,
            write: Epoch::new(client_secret)?,
            handshake: Vec::new(),
            tickets: 0,
            server_updates: 0,
        })
    }

    /// Encrypt an outgoing application record.
    pub fn send(&mut self, content: &[u8]) -> Result<Vec<u8>> {
        self.write.encrypt(content, 23)
    }

    /// Return the current client traffic secret and next TLS record sequence.
    pub fn client_state(&self) -> (&[u8; 32], u64) {
        (self.write.secret(), self.write.sequence())
    }

    /// Authenticate one incoming record and return its application bytes, if any.
    pub fn receive(&mut self, wire: &[u8]) -> Result<Option<Vec<u8>>> {
        let (kind, content) = self.read.decrypt(wire)?;
        match kind {
            23 => Ok(Some(content)),
            21 => bail!(
                "TLS alert {}",
                content
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            ),
            22 => {
                self.handshake.extend_from_slice(&content);
                while self.handshake.len() >= 4 {
                    let size = u32::from_be_bytes([
                        0,
                        self.handshake[1],
                        self.handshake[2],
                        self.handshake[3],
                    ]) as usize
                        + 4;
                    if self.handshake.len() < size {
                        break;
                    }
                    let message: Vec<_> = self.handshake.drain(..size).collect();
                    if message[0] == 4 {
                        self.tickets += 1;
                    } else {
                        ensure!(
                            message == [24, 0, 0, 1, 0],
                            "unsupported TLS post-handshake message"
                        );
                        ensure!(
                            self.handshake.is_empty(),
                            "KeyUpdate shares a record with another message"
                        );
                        self.read = self.read.updated()?;
                        self.server_updates += 1;
                    }
                }
                Ok(None)
            }
            _ => bail!("unexpected TLS inner content type {kind}"),
        }
    }

    /// Number of authenticated NewSessionTicket messages.
    pub fn tickets(&self) -> usize {
        self.tickets
    }

    /// Number of authenticated server KeyUpdates.
    pub fn server_updates(&self) -> usize {
        self.server_updates
    }
}
