"""Synthetic Responses provider that makes Codex read one file per tool turn."""

import base64
import hashlib
import json
import os
import time
import uuid

from codex_tool_loop_provider import ToolLoopProvider, link_counters
from spike_fixtures import response_events, response_value
from sustained_claude_fixture import summary


class SustainedToolProvider(ToolLoopProvider):
    """Require each real Codex tool result before issuing the next file read."""

    def do_GET(self):
        """Serve one admitted WebSocket connection across warmup and all tool turns."""
        token = self.headers.get("Authorization", "").removeprefix("Bearer ")
        credential = self.server.state.credentials.get(token, {})
        if (self.path != "/backend-api/codex/responses" or self.headers.get("Host") != "chatgpt.com"
                or credential.get("route") != "chatgpt"
                or self.headers.get("ChatGPT-Account-Id") != credential.get("account")):
            self.send_error(401)
            return
        connection = uuid.uuid4().hex
        self.server.state.calls.append({"kind": "connection", "id": connection,
                                        "at": time.monotonic(), "transport": "websocket",
                                        "auth_matches": True})
        accept = base64.b64encode(hashlib.sha1(
            self.headers["Sec-WebSocket-Key"].encode()
            + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest()).decode()
        self.sized = True
        self.send_response(101)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        steps = int(os.environ["TOOL_LOOP_STEPS"])
        completed = 0
        request_count = 0
        last_call = None
        while True:
            try:
                request = self.read_message()
            except (EOFError, ConnectionResetError):
                break
            if request is None:
                break
            request_count += 1
            row = {"kind": "request", "connection": connection,
                   "request_index": request_count, "arrived_monotonic": time.monotonic(),
                   "wan_at_arrival": link_counters(), "body": request,
                   "auth_matches": True}
            with self.server.state.lock:
                self.server.state.calls.append(row)
            if request.get("type") != "response.create":
                row["error"] = "unexpected request type"
                raise ValueError(row["error"])
            parent = request.get("previous_response_id")
            if parent is not None and parent not in self.server.response_ids:
                row["error"] = "unknown previous response"
                raise ValueError(row["error"])
            row["previous_response_id"] = parent
            if request.get("generate") is False:
                if request_count != 1 or completed:
                    row["error"] = "unexpected warmup"
                    raise ValueError(row["error"])
                value = response_value(request["model"], "fixture")
                value["previous_response_id"] = parent
                events = response_events(value)
                row["warmup"] = True
            else:
                outputs = [item for item in request.get("input", [])
                           if isinstance(item, dict) and item.get("type") == "function_call_output"]
                if last_call:
                    matching = [item for item in outputs if item.get("call_id") == last_call]
                    if len(matching) != 1 or f"topic-{completed:02d}" not in str(matching[0].get("output")):
                        row["error"] = "missing or incorrect real tool output"
                        raise ValueError(row["error"])
                    row["validated_tool_output_sha256"] = hashlib.sha256(
                        json.dumps(matching[0], sort_keys=True).encode()).hexdigest()
                elif outputs:
                    row["error"] = "unexpected initial tool output"
                    raise ValueError(row["error"])
                if completed < steps:
                    completed += 1
                    call_id = "call_" + uuid.uuid4().hex
                    last_call = call_id
                    command = f"cat file-{completed:02d}.txt"
                    arguments = json.dumps({"cmd": command})
                    item = {"type": "function_call", "id": "fc_" + uuid.uuid4().hex,
                            "call_id": call_id, "name": "exec_command",
                            "arguments": arguments, "status": "completed"}
                    value = response_value(request["model"], "unused")
                    value["output"] = [item]
                    value["previous_response_id"] = parent
                    events = [
                        {"type": "response.created", "response": {**value, "status": "in_progress",
                                                                 "output": [], "usage": None}},
                        {"type": "response.output_item.added", "output_index": 0,
                         "item": {**item, "arguments": "", "status": "in_progress"}},
                        {"type": "response.function_call_arguments.delta", "item_id": item["id"],
                         "output_index": 0, "delta": arguments},
                        {"type": "response.function_call_arguments.done", "item_id": item["id"],
                         "output_index": 0, "arguments": arguments},
                        {"type": "response.output_item.done", "output_index": 0, "item": item},
                        {"type": "response.completed", "response": value},
                    ]
                    row["issued_call_id"] = call_id
                    row["issued_command"] = command
                else:
                    value = response_value(request["model"], "unused")
                    value["output"][0]["content"][0]["text"] = json.dumps(summary(steps))
                    value["previous_response_id"] = parent
                    events = response_events(value)
                    row["final"] = True
            row["response_id"] = value["id"]
            self.server.response_ids.add(value["id"])
            for event in events:
                self.send_frame(json.dumps(event, separators=(",", ":")).encode())
            row["completed_monotonic"] = time.monotonic()
            row["wan_at_completion"] = link_counters()
