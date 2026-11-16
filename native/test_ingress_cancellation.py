"""Exercise local cancellation at the two interleavings that can hide it."""

import importlib.util
import io
import pathlib
import sys
import threading
import types
import unittest
from email.message import Message
from unittest import mock


stub = types.SimpleNamespace(receive=None, send=None)
with mock.patch.dict(sys.modules, {'tls13_product_http_h2': stub}):
    spec = importlib.util.spec_from_file_location(
        'native_ingress_under_test', pathlib.Path(__file__).parent / 'worker/ingress.py')
    ingress = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ingress)


class IngressCancellationTests(unittest.TestCase):
    """Keep local disconnects effective during response writes and turn handoff."""

    def test_claude_write_failure_cancels_without_disconnect_watcher(self):
        """A failed local chunk write ends the native session immediately."""
        headers = Message()
        headers['Authorization'] = 'Bearer local-relay-placeholder'
        headers['Content-Length'] = '2'
        handler = types.SimpleNamespace(
            path='/v1/messages', headers=headers, rfile=io.BytesIO(b'{}'),
            connection=object(), close_connection=False,
            server=types.SimpleNamespace(lock=threading.Lock(), first_metadata={},
                                         first=threading.Event(), bridge=object()),
            send_response=mock.Mock(), send_header=mock.Mock(), end_headers=mock.Mock(),
            send_error=mock.Mock(),
            wfile=types.SimpleNamespace(write=mock.Mock(side_effect=BrokenPipeError(32, 'closed')),
                                        flush=mock.Mock()))
        responses = [{'kind': 'response_start', 'status': 200,
                      'content_type': 'text/event-stream'},
                     {'kind': 'response_chunk', 'data': b'event: message_start\n\n'}]
        with (mock.patch.object(ingress, 'watch_disconnect'),
              mock.patch.object(ingress, 'send'),
              mock.patch.object(ingress, 'receive', side_effect=responses),
              mock.patch.object(ingress, 'cancel_native') as canceled):
            ingress.ClaudeRequest.do_POST(handler)
        canceled.assert_called_once_with('cli_write_failed')
        self.assertTrue(handler.close_connection)
        handler.send_error.assert_not_called()

    def test_codex_next_turn_stays_cancelable_across_completion(self):
        """A queued turn cannot be hidden by the previous turn's finish."""
        pending = ingress.PendingTurns()
        pending.enqueue({'type': 'response.create', 'first': True})
        self.assertTrue(pending.requests.get()['first'])
        pending.enqueue({'type': 'response.create', 'second': True})
        pending.finished()
        self.assertTrue(pending.cancel())

    def test_codex_enqueue_during_empty_check_stays_cancelable(self):
        """Enqueue after the empty check must serialize with activity clearing."""
        pending = ingress.PendingTurns()
        pending.enqueue({'type': 'response.create', 'first': True})
        pending.requests.get()
        checked = threading.Event()
        attempted = threading.Event()
        release = threading.Event()
        timed_out = threading.Event()

        def empty_between_turns():
            """Pause completion just after it observes an empty queue."""
            checked.set()
            if not release.wait(2):
                timed_out.set()
            return True

        def enqueue_next():
            """Attempt to queue the next turn while completion is paused."""
            attempted.set()
            pending.enqueue({'type': 'response.create', 'second': True})

        with mock.patch.object(pending.requests, 'empty', side_effect=empty_between_turns):
            finishing = threading.Thread(target=pending.finished)
            finishing.start()
            self.assertTrue(checked.wait(2))
            enqueueing = threading.Thread(target=enqueue_next)
            enqueueing.start()
            self.assertTrue(attempted.wait(2))
            release.set()
            finishing.join(2)
            enqueueing.join(2)
        self.assertFalse(finishing.is_alive())
        self.assertFalse(enqueueing.is_alive())
        self.assertFalse(timed_out.is_set())
        self.assertTrue(pending.requests.get()['second'])
        self.assertTrue(pending.cancel())


if __name__ == '__main__':
    unittest.main()
