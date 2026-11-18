#include "../ssl/TLSSocket.hpp"
#include "../ssl/TestUtil.hpp"
#include "../ssl/EmpWrapper.hpp"
#include <emp-ag2pc/2pc.h>
#include <chrono>
#include <cstring>
#include <iostream>
#include <memory>
#include <vector>
#include <sys/stat.h>
#include <openssl/x509v3.h>
#include <openssl/crypto.h>

/** Return elapsed wall time in milliseconds for diagnostic phase accounting. */
static double elapsed(std::chrono::steady_clock::time_point start) {
  return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
}

/** Execute one circuit using synthetic localhost TLS, private stdin and public stdout. */
int main(int argc, char **argv) {
  if (argc < 3) { std::cerr << "usage: HandoffParty PARTY CIRCUIT [PORT]\n"; return 1; }
  umask(077);
  const auto started = std::chrono::steady_clock::now();
  const int party = std::stoi(argv[1]);
  if (party != emp::ALICE && party != emp::BOB) return 1;
  emp::BristolFormat circuit(argv[2]);
  if (circuit.n1 != circuit.n2 || circuit.n1 % 8 || circuit.n3 % 8) return 2;
  const auto input_bits = static_cast<size_t>(circuit.n1);
  std::vector<uint8_t> input(input_bits / 8);
  auto bits = std::make_unique<bool[]>(input_bits * 2);
  const size_t offset = party == emp::ALICE ? input_bits : 0;
  auto output = std::make_unique<bool[]>(static_cast<size_t>(circuit.n3));
  const double load_ms = elapsed(started);

  const char *ca = std::getenv("HANDOFF_PEER_CA");
  const char *cert = std::getenv("HANDOFF_PEER_CERT");
  const char *key = std::getenv("HANDOFF_PEER_KEY");
  const bool authenticated = ca && cert && key;
  if (std::getenv("HANDOFF_REQUIRE_AUTH") && !authenticated) return 4;
  auto context = authenticated ? bssl::UniquePtr<SSL_CTX>(SSL_CTX_new(TLS_method()))
                               : CreateContextWithTestCertificate(TLS_method());
  if (!context) return 4;
  if (authenticated &&
      (!SSL_CTX_use_certificate_file(context.get(), cert, SSL_FILETYPE_PEM) ||
       !SSL_CTX_use_PrivateKey_file(context.get(), key, SSL_FILETYPE_PEM) ||
       !SSL_CTX_check_private_key(context.get()) ||
       !SSL_CTX_load_verify_locations(context.get(), ca, nullptr))) return 4;
  if (authenticated)
    SSL_CTX_set_verify(context.get(), SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
  TLSSocket socket(context.get(), party == emp::ALICE);
  if (!socket.set_ip_v4()) return 4;
  if (party == emp::ALICE) {
    uint16_t port = 0;
    const char *bind_host = std::getenv("HANDOFF_MPC_BIND_HOST");
    if (!socket.set_addr(bind_host ? bind_host : "127.0.0.1") || !socket.bind() || !socket.listen(1) || !socket.get_portnumber(&port)) return 4;
    std::cerr << "HANDOFF_READY " << port << std::endl;
    if (!socket.accept() || socket.do_handshake() != 1) {
      std::cerr << "HANDOFF_AUTH server handshake failed\n";
      ERR_print_errors_fp(stderr);
      return 4;
    }
  } else {
    const char *connect_host = std::getenv("HANDOFF_MPC_CONNECT_HOST");
    if (argc != 4 || !socket.connect_to(connect_host ? connect_host : "127.0.0.1",
                                        static_cast<uint16_t>(std::stoi(argv[3])))) {
      std::cerr << "HANDOFF_AUTH client handshake failed\n";
      ERR_print_errors_fp(stderr);
      return 4;
    }
  }
  if (authenticated) {
    bssl::UniquePtr<X509> peer(SSL_get_peer_certificate(socket.get_ssl_object()));
    const char *expected = party == emp::ALICE ? "concurro.local" : "sponsor.local";
    if (!peer || SSL_get_verify_result(socket.get_ssl_object()) != X509_V_OK ||
        X509_check_host(peer.get(), expected, std::strlen(expected), 0, nullptr) != 1) {
      std::cerr << "HANDOFF_AUTH peer identity failed: role " << party
                << " result " << SSL_get_verify_result(socket.get_ssl_object()) << '\n';
      return 4;
    }
  }

  const char *session_binding = std::getenv("HANDOFF_MPC_SESSION_BINDING");
  if (std::getenv("HANDOFF_REQUIRE_AUTH") && !session_binding) {
    std::cerr << "HANDOFF_SESSION missing binding\n";
    return 4;
  }
  if (session_binding) {
    if (std::strlen(session_binding) != 64) {
      std::cerr << "HANDOFF_SESSION invalid binding\n";
      return 4;
    }
    char peer_binding[64];
    SSL *const ssl = socket.get_ssl_object();
    if (party == emp::ALICE) {
      Util::process_data(ssl, session_binding, sizeof(peer_binding), SSL_write);
      Util::process_data(ssl, peer_binding, sizeof(peer_binding), SSL_read);
    } else {
      Util::process_data(ssl, peer_binding, sizeof(peer_binding), SSL_read);
      Util::process_data(ssl, session_binding, sizeof(peer_binding), SSL_write);
    }
    if (CRYPTO_memcmp(session_binding, peer_binding, sizeof(peer_binding)) != 0) {
      std::cerr << "HANDOFF_SESSION peer binding differs\n";
      return 4;
    }
  }

  EmpWrapper<> channel(socket.get_ssl_object());
  EmpWrapper<> *channels[2] = {&channel, &channel};
  const auto setup_start = std::chrono::steady_clock::now();
  emp::C2PC<EmpWrapper<>, 1, emp::FerretCOT> protocol(channels, party, 9, &circuit);
  const double setup_ms = elapsed(setup_start);
  const auto setup_read = channel.get_read_counter(), setup_write = channel.get_write_counter();
  const auto preproc_start = std::chrono::steady_clock::now();
  std::cerr << "HANDOFF_PHASE independent" << std::endl;
  protocol.function_independent();
  const auto independent_read = channel.get_read_counter(), independent_write = channel.get_write_counter();
  size_t zero_triple_blocks = 0;
  const auto zero_block = emp::makeBlock(0, 0);
  for (int i = 0; i < protocol.num_ands * 3; ++i) {
    if (emp::cmpBlock(protocol.fpre->MAC_res() + i, &zero_block, 1) &&
        emp::cmpBlock(protocol.fpre->KEY_res() + i, &zero_block, 1)) ++zero_triple_blocks;
  }
  std::cerr << "HANDOFF_TRIPLES {\"zero_auth_pairs\":" << zero_triple_blocks << "}" << std::endl;
  std::cerr << "HANDOFF_PHASE dependent" << std::endl;
  protocol.function_dependent();
  const auto dependent_read = channel.get_read_counter(), dependent_write = channel.get_write_counter();
  const double preproc_ms = elapsed(preproc_start);
  std::cerr << "HANDOFF_PREPARED" << std::endl;
  std::cin.read(reinterpret_cast<char *>(input.data()), static_cast<std::streamsize>(input.size()));
  if (std::cin.gcount() != static_cast<std::streamsize>(input.size())) return 3;
  for (size_t i = 0; i < input_bits; ++i) bits[offset + i] = (input[i / 8] >> (i % 8)) & 1;
  std::cerr << "HANDOFF_PHASE online" << std::endl;
  const auto online_start = std::chrono::steady_clock::now();
  if (std::getenv("HANDOFF_TEST_CORRUPT_OUTPUT_MAC")) {
    protocol.mac[circuit.num_wire - circuit.n3] =
        protocol.mac[circuit.num_wire - circuit.n3] ^ emp::makeBlock(0, 0x8000);
  }
  protocol.online(bits.get(), output.get(), true);
  const auto online_read = channel.get_read_counter(), online_write = channel.get_write_counter();
  const double online_ms = elapsed(online_start);
  std::vector<uint8_t> bytes(static_cast<size_t>(circuit.n3) / 8);
  for (size_t i = 0; i < static_cast<size_t>(circuit.n3); ++i) bytes[i / 8] |= static_cast<uint8_t>(output[i] << (i % 8));
  std::cout.write(reinterpret_cast<const char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  std::cout.flush();
  std::cerr << "HANDOFF_METRICS {\"party\":" << party << ",\"load_ms\":" << load_ms
            << ",\"setup_ms\":" << setup_ms << ",\"preprocess_ms\":" << preproc_ms
            << ",\"online_ms\":" << online_ms << ",\"elapsed_ms\":" << elapsed(started)
            << ",\"read_bytes\":" << channel.get_read_counter()
            << ",\"write_bytes\":" << channel.get_write_counter() << "}" << std::endl;
  std::cerr << "HANDOFF_TRAFFIC {\"setup\":[" << setup_read << ',' << setup_write
            << "],\"independent\":[" << independent_read - setup_read << ',' << independent_write - setup_write
            << "],\"dependent\":[" << dependent_read - independent_read << ',' << dependent_write - independent_write
            << "],\"online\":[" << online_read - dependent_read << ',' << online_write - dependent_write
            << "]}" << std::endl;
}
