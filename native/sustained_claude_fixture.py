"""Synthetic Claude H2 provider for a sustained, tool-driven directory summary."""

import argparse
import hashlib
import json
import runpy
import socket
import ssl
import sys
import time
import uuid
from pathlib import Path

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, RequestReceived, StreamEnded


def summary(steps):
    """Return the plan-schema result derived from the expected file contents."""
    names = [f"file-{index:02d}.txt" for index in range(1, steps + 1)]
    return {
        "headline": "Synthetic directory summary",
        "summary": "\n".join(f"{name}: topic-{index:02d}" for index, name in enumerate(names, 1)),
        "questions": [],
        "files": names,
        "scope": {"paths": ["."]},
        "steps": ["Read each synthetic file through a CLI tool"],
        "tests": ["Validated every returned tool result"],
        "responses": [],
        "publication": {"changes": ["Summarized the synthetic directory"],
                        "review_focus": ["Tool-result continuity"]},
    }


def tool_result(request, call_id, expected):
    """Require the CLI's next request to contain the actual result of the previous tool."""
    matches = [item for message in request.get("messages", [])
               for item in message.get("content", []) if isinstance(item, dict)
               and item.get("type") == "tool_result" and item.get("tool_use_id") == call_id]
    if len(matches) != 1 or expected not in json.dumps(matches[0], ensure_ascii=False):
        raise ValueError(f"missing or incorrect tool result for {call_id}")
    return hashlib.sha256(json.dumps(matches[0], sort_keys=True).encode()).hexdigest()


def response_events(request, base_events, index, steps):
    """Issue the next Bash read, or a structured summary after all reads succeeded."""
    events = base_events(request, "unused")
    if not any(tool.get("name") == "StructuredOutput" for tool in request.get("tools", [])):
        raise ValueError("CLI did not request structured output")
    if index < steps:
        call_id = "toolu_" + uuid.uuid4().hex
        events[1]["content_block"] = {"type": "tool_use", "id": call_id,
                                      "name": "Bash", "input": {}}
        events[2]["delta"] = {"type": "input_json_delta", "partial_json":
                              json.dumps({"command": f"cat file-{index + 1:02d}.txt"})}
        return events, call_id
    events[2]["delta"] = {"type": "input_json_delta", "partial_json": json.dumps(summary(steps))}
    return events, None


def serve(listener, certs, source, steps, stop_file, result, expire_once_at):
    """Serve sequential Claude requests on one authenticated TLS 1.3 H2 connection."""
    sys.path.insert(0, str(source))
    baseline = runpy.run_path(str(source / "run_cli.py"))
    base_events = baseline["claude_events"]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(["h2"])
    context.load_cert_chain(certs / "chain-provider.pem", certs / "chain-provider.key")
    context.set_ecdh_curve("prime256v1")
    connection = None
    last_call = None
    thread_parent = None
    thread_tools = None
    expired = False
    try:
        raw, _ = listener.accept()
        connection = context.wrap_socket(raw, server_side=True)
        connection.settimeout(.5)
        result["connections"] = 1
        h2 = H2Connection(config=H2Configuration(client_side=False, header_encoding=None))
        h2.initiate_connection()
        connection.sendall(h2.data_to_send())
        pending = {}
        while True:
            if stop_file.exists() and len(result["requests"]) == steps + 1:
                break
            try:
                data = connection.recv(65536)
            except socket.timeout:
                continue
            if not data:
                if len(result["requests"]) == steps + 1:
                    break
                raise EOFError("provider connection ended before the final result")
            for event in h2.receive_data(data):
                if isinstance(event, RequestReceived):
                    headers = dict(event.headers)
                    if headers.get(b"authorization") != b"Bearer " + b"X" * 44:
                        raise ValueError("synthetic provider authorization failed")
                    pending[event.stream_id] = {"body": bytearray(), "headers": headers}
                elif isinstance(event, DataReceived):
                    pending[event.stream_id]["body"].extend(event.data)
                    h2.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                elif isinstance(event, StreamEnded):
                    received = pending.pop(event.stream_id)
                    body = bytes(received["body"])
                    request = json.loads(body)
                    thread = request.get("thread") or {}
                    mode = thread.get("type", "full")
                    if mode != "full":
                        betas = received["headers"].get(b"anthropic-beta", b"")
                        if b"message-threads-2026-08-12" not in betas:
                            raise ValueError("Message Threads beta header missing")
                    if mode == "create":
                        thread_tools = request.get("tools")
                    elif mode == "continue":
                        if thread.get("previous_message_id") != thread_parent:
                            raise ValueError("continuation did not use the last provider response")
                        if "system" in request or "tools" in request:
                            raise ValueError("continuation repeated create-only fields")
                    elif mode != "full":
                        raise ValueError("invalid thread mode")
                    index = len(result["requests"])
                    if index > steps:
                        raise ValueError("extra model request")
                    if mode == "continue" and index == expire_once_at and not expired:
                        expired = True
                        result["errors"].append({"status": 404, "error_code": "thread_not_found",
                                                 "parent": thread.get("previous_message_id")})
                        error = {"type": "error", "error": {"type": "not_found_error",
                                 "details": {"error_code": "thread_not_found"}}}
                        h2.send_headers(event.stream_id, [(b":status", b"404"),
                                                          (b"content-type", b"application/json")])
                        h2.send_data(event.stream_id, json.dumps(error).encode(), end_stream=True)
                        continue
                    row = {"stream": event.stream_id, "body_bytes": len(body),
                           "thread_mode": mode, "parent": thread.get("previous_message_id"),
                           "message_count": len(request.get("messages", [])),
                           "arrived_monotonic": time.monotonic(),
                           "input_tokens": 2, "output_tokens": 3,
                           "input_types": [item.get("type") for message in request.get("messages", [])
                                           for item in message.get("content", []) if isinstance(item, dict)]}
                    if last_call:
                        row["validated_tool_output_sha256"] = tool_result(
                            request, last_call, f"topic-{index:02d}")
                    effective = {**request, "tools": thread_tools} if mode == "continue" else request
                    events, last_call = response_events(effective, base_events, index, steps)
                    thread_parent = events[0]["message"]["id"]
                    row["issued_tool_id"] = last_call
                    result["requests"].append(row)
                    payload = b"".join(b"event: " + item["type"].encode() + b"\ndata: "
                                       + json.dumps(item, separators=(",", ":")).encode() + b"\n\n"
                                       for item in events)
                    h2.send_headers(event.stream_id, [(b":status", b"200"),
                                                      (b"content-type", b"text/event-stream")])
                    row["first_event_monotonic"] = time.monotonic()
                    h2.send_data(event.stream_id, payload, end_stream=True)
                    row["completed_monotonic"] = time.monotonic()
            outgoing = h2.data_to_send()
            if outgoing:
                connection.sendall(outgoing)
    except BaseException as error:
        result["error"] = repr(error)
    finally:
        if connection is not None:
            connection.close()
        listener.close()


def main():
    """Run one local synthetic provider and print its nonsecret request journal."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--certs", type=Path, required=True)
    parser.add_argument("--steps", type=int, required=True)
    parser.add_argument("--stop-file", type=Path, required=True)
    parser.add_argument("--expire-once-at", type=int, default=-1,
                        help="Return one thread_not_found at this successful request index")
    args = parser.parse_args()
    if args.steps < 1:
        parser.error("--steps must be positive")
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    print(json.dumps({"port": listener.getsockname()[1]}), flush=True)
    result = {"requests": [], "errors": [], "connections": 0}
    serve(listener, args.certs, args.source, args.steps, args.stop_file, result, args.expire_once_at)
    print(json.dumps(result), flush=True)
    return 1 if "error" in result else 0


if __name__ == "__main__":
    sys.exit(main())
