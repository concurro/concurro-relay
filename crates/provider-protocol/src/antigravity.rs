//! Antigravity subscription GenerateContent SSE normalization.

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

use crate::ResponseSummary;

/// Normalize a completed authenticated Google SSE response without altering its body.
pub fn summarize_sse(
    status: u16,
    headers: &[(Vec<u8>, Vec<u8>)],
    body: &[u8],
) -> Result<ResponseSummary> {
    ensure!(status == 200, "Antigravity returned HTTP {status}");
    ensure!(
        headers.iter().any(|(name, value)| name == b"content-type"
            && value
                .windows(b"text/event-stream".len())
                .any(|part| part == b"text/event-stream")),
        "Antigravity response is not SSE"
    );
    let mut message_id = None;
    let mut usage = None;
    let mut finished = false;
    let mut tool_uses = Vec::new();
    for line in body.split(|byte| *byte == b'\n') {
        let Some(data) = line.strip_prefix(b"data:") else {
            continue;
        };
        let event: Value = serde_json::from_slice(data)?;
        ensure!(
            event.get("error").is_none(),
            "Antigravity returned an SSE error"
        );
        let response = event.get("response").unwrap_or(&event);
        ensure!(
            response.get("error").is_none(),
            "Antigravity returned an inference error"
        );
        if let Some(id) = response["responseId"]
            .as_str()
            .or_else(|| event["traceId"].as_str())
        {
            message_id = Some(id.to_owned());
        }
        if response["usageMetadata"].is_object() {
            usage = Some(response["usageMetadata"].clone());
        }
        if let Some(candidates) = response["candidates"].as_array() {
            for candidate in candidates {
                finished |= candidate["finishReason"].as_str().is_some_and(|reason| {
                    !reason.is_empty() && reason != "FINISH_REASON_UNSPECIFIED"
                });
                if let Some(parts) = candidate["content"]["parts"].as_array() {
                    for part in parts {
                        if let Some(name) = part["functionCall"]["name"].as_str() {
                            tool_uses.push(name.to_owned());
                        }
                    }
                }
            }
        }
    }
    ensure!(finished, "Antigravity response did not finish");
    let raw = usage.context("Antigravity usage missing")?;
    let prompt = raw["promptTokenCount"]
        .as_u64()
        .context("Antigravity prompt usage missing")?;
    let input = prompt
        .checked_add(raw["toolUsePromptTokenCount"].as_u64().unwrap_or(0))
        .context("Antigravity input usage overflow")?;
    let output = raw["candidatesTokenCount"]
        .as_u64()
        .unwrap_or(0)
        .checked_add(raw["thoughtsTokenCount"].as_u64().unwrap_or(0))
        .context("Antigravity output usage overflow")?;
    Ok(ResponseSummary {
        message_id: message_id.context("Antigravity response ID missing")?,
        usage: json!({"input_tokens":input,"output_tokens":output,"google":raw}),
        tool_uses,
    })
}

#[cfg(test)]
mod tests {
    use super::summarize_sse;
    use serde_json::json;

    /// Normalize subscription envelopes, tool calls and final cumulative usage.
    #[test]
    fn subscription_response_usage() {
        let headers = vec![(
            b"content-type".to_vec(),
            b"text/event-stream; charset=utf-8".to_vec(),
        )];
        let start = json!({"response":{"responseId":"google-1","usageMetadata":{"promptTokenCount":5},"candidates":[{"content":{"parts":[{"functionCall":{"name":"read_file","args":{"path":"README.md"}}}]}}]}});
        let end = json!({"response":{"responseId":"google-1","candidates":[{"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":10,"cachedContentTokenCount":4,"toolUsePromptTokenCount":2,"candidatesTokenCount":3,"thoughtsTokenCount":7}}});
        let body = format!("data: {start}\r\n\r\ndata: {end}\n\n");
        let summary = summarize_sse(200, &headers, body.as_bytes()).unwrap();
        assert_eq!(summary.message_id, "google-1");
        assert_eq!(summary.tool_uses, ["read_file"]);
        assert_eq!(summary.usage["input_tokens"], 12);
        assert_eq!(summary.usage["output_tokens"], 10);
        assert_eq!(summary.usage["google"]["cachedContentTokenCount"], 4);
        assert!(summarize_sse(403, &headers, body.as_bytes()).is_err());
        assert!(summarize_sse(200, &[], body.as_bytes()).is_err());
        for invalid in [
            format!("data: {start}\n"),
            "data: {\"error\":{\"message\":\"failed\"}}\n".into(),
            "data: {\"response\":{\"error\":{\"message\":\"failed\"}}}\n".into(),
            "data: {\"response\":{\"responseId\":\"upgrade\",\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"upgrade required\"}]}}]}}\n".into(),
        ] {
            assert!(summarize_sse(200, &headers, invalid.as_bytes()).is_err());
        }
    }
}
