"""Exercise concurrent native byte channels and half-close over one link."""

import socket
import threading
import unittest

from tunnel import Tunnel


class TunnelTests(unittest.TestCase):
    """Check that registered native ports share an authenticated byte stream."""

    def test_parallel_streams_and_half_close(self):
        """Carry two large independent TCP exchanges without mixing bytes."""
        left, right = socket.socketpair()
        sponsor = Tunnel(left, 'sponsor').start()
        concurro = Tunnel(right, 'concurro').start()
        upstream = socket.socket()
        upstream.bind(('127.0.0.1', 0))
        upstream.listen(2)
        target = upstream.getsockname()[1]
        expected = [b'a' * 150000, b'b' * 210000]
        received = []

        def serve_one():
            """Return the complete request after its write half closes."""
            with upstream.accept()[0] as peer:
                body = bytearray()
                while chunk := peer.recv(32768):
                    body.extend(chunk)
                received.append(bytes(body))
                peer.sendall(bytes(body))

        servers = [threading.Thread(target=serve_one) for _ in expected]
        for server in servers:
            server.start()
        port = sponsor.register(target)
        self.assertEqual(concurro.wait_target(target), port)
        answers = []

        def client(body):
            """Send one distinct native payload through the registered port."""
            with socket.create_connection(('127.0.0.1', port)) as peer:
                peer.sendall(body)
                peer.shutdown(socket.SHUT_WR)
                answer = bytearray()
                while chunk := peer.recv(32768):
                    answer.extend(chunk)
                answers.append(bytes(answer))

        clients = [threading.Thread(target=client, args=(body,)) for body in expected]
        for worker in clients:
            worker.start()
        for worker in clients + servers:
            worker.join(timeout=15)
            self.assertFalse(worker.is_alive())
        self.assertCountEqual(received, expected)
        self.assertCountEqual(answers, expected)
        self.assertIsNone(sponsor.error)
        self.assertIsNone(concurro.error)
        upstream.close()
        sponsor.close()
        concurro.close()


if __name__ == '__main__':
    unittest.main()
