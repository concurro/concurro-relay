//! Length-prefixed JSON control messages shared by native roles.

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum encoded JSON body accepted by the Python reference.
pub const MAX_MESSAGE: usize = 1_000_000;

/// One decoded native control message.
#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    /// Message kind.
    pub kind: String,
    /// Decoded binary payload.
    pub data: Vec<u8>,
    /// Additional JSON fields such as turn, port or phase.
    pub metadata: Map<String, Value>,
}

/// JSON fields in the Python worker's serialized order.
#[derive(Deserialize, Serialize)]
struct WireMessage {
    /// Message kind.
    kind: String,
    /// Base64-encoded binary payload.
    data: String,
    /// Additional JSON fields.
    #[serde(flatten)]
    metadata: Map<String, Value>,
}

/// Write one Python-compatible bounded control frame.
pub async fn send<W: AsyncWrite + Unpin>(writer: &mut W, message: &Message) -> Result<()> {
    ensure!(
        !message.metadata.contains_key("kind") && !message.metadata.contains_key("data"),
        "reserved control metadata field"
    );
    let wire = WireMessage {
        kind: message.kind.clone(),
        data: STANDARD.encode(&message.data),
        metadata: message.metadata.clone(),
    };
    let body = serde_json::to_vec(&wire)?;
    ensure!(body.len() <= MAX_MESSAGE, "control message too large");
    writer.write_all(&(body.len() as u32).to_be_bytes()).await?;
    writer.write_all(&body).await?;
    Ok(())
}

/// Read one bounded control frame, including fragmented input and EOF errors.
pub async fn receive<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Message> {
    let mut length = [0; 4];
    reader
        .read_exact(&mut length)
        .await
        .context("control frame length")?;
    let length = u32::from_be_bytes(length) as usize;
    ensure!(length <= MAX_MESSAGE, "oversize control message");
    let mut body = vec![0; length];
    reader
        .read_exact(&mut body)
        .await
        .context("control frame body")?;
    let wire: WireMessage = serde_json::from_slice(&body)?;
    Ok(Message {
        kind: wire.kind,
        data: STANDARD
            .decode(wire.data)
            .context("invalid control base64")?,
        metadata: wire.metadata,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::{Map, json};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::{MAX_MESSAGE, Message, receive, send};

    /// Match the frozen Python wire bytes and decode fragmented reads.
    #[tokio::test]
    async fn fixture_wire_and_fragments() {
        let mut metadata = Map::new();
        metadata.insert("turn".into(), json!(2));
        let message = Message {
            kind: "fixture".into(),
            data: vec![0, 255],
            metadata,
        };
        let (mut writer, mut reader) = tokio::io::duplex(256);
        send(&mut writer, &message).await.unwrap();
        let mut frame = vec![0; 4 + r#"{"kind":"fixture","data":"AP8=","turn":2}"#.len()];
        reader.read_exact(&mut frame).await.unwrap();
        assert_eq!(&frame[4..], br#"{"kind":"fixture","data":"AP8=","turn":2}"#);
        assert_eq!(
            u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize,
            frame.len() - 4
        );
        let (mut writer, mut reader) = tokio::io::duplex(2);
        let sending = tokio::spawn(async move {
            for byte in frame {
                writer.write_all(&[byte]).await.unwrap();
            }
        });
        assert_eq!(receive(&mut reader).await.unwrap(), message);
        sending.await.unwrap();
    }

    /// Reject a size above the Python cap before allocating a body.
    #[tokio::test]
    async fn limits_and_eof() {
        let (mut writer, mut reader) = tokio::io::duplex(16);
        writer
            .write_all(&((MAX_MESSAGE + 1) as u32).to_be_bytes())
            .await
            .unwrap();
        assert!(
            receive(&mut reader)
                .await
                .unwrap_err()
                .to_string()
                .contains("oversize")
        );
        let oversized = Message {
            kind: "large".into(),
            data: vec![0; MAX_MESSAGE],
            metadata: Map::new(),
        };
        assert!(send(&mut writer, &oversized).await.is_err());
        let (mut writer, mut reader) = tokio::io::duplex(16);
        writer.write_all(&5u32.to_be_bytes()).await.unwrap();
        writer.write_all(b"ab").await.unwrap();
        drop(writer);
        assert!(receive(&mut reader).await.is_err());
        let (mut writer, mut reader) = tokio::io::duplex(16);
        writer.write_all(&[0, 0]).await.unwrap();
        drop(writer);
        assert!(receive(&mut reader).await.is_err());
    }
}
