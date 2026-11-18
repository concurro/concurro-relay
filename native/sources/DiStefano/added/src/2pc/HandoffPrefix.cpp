#include "HandoffPrefix.hpp"
#include <iostream>

/** Generate or locally evaluate the protected-prefix circuit with an explicit public shape. */
int main(int argc, char **argv) {
  if (argc < 5) { std::cerr << "usage: HandoffPrefix generate|source|circuit HEAD_BYTES TOKEN_OFFSET TOKEN_BYTES [CIRCUIT]\n"; return 1; }
  const std::string mode(argv[1]);
  const auto size = std::stoull(argv[2]), token_offset = std::stoull(argv[3]), token_bytes = std::stoull(argv[4]);
  std::vector<uint8_t> alice(HandoffPrefix::fixed_input_bytes+size), bob(alice.size());
  if (mode == "generate") {
    if (argc != 6) return 1;
    emp::setup_plain_prot(true, argv[5]);
    HandoffPrefix::evaluate(alice, bob, token_offset, token_bytes);
    emp::finalize_plain_prot();
    return 0;
  }
  for (auto *input : {&alice, &bob}) {
    std::cin.read(reinterpret_cast<char *>(input->data()), static_cast<std::streamsize>(input->size()));
    if (std::cin.gcount() != static_cast<std::streamsize>(input->size())) return 2;
  }
  emp::setup_plain_prot(false, "");
  std::vector<uint8_t> output(HandoffPrefix::output_bytes(size));
  if (mode == "source") {
    output = HandoffPrefix::evaluate(alice, bob, token_offset, token_bytes);
  } else if (mode == "circuit" && argc == 6) {
    emp::BristolFormat circuit(argv[5]);
    if (circuit.n1 != int(alice.size()*8) || circuit.n2 != int(bob.size()*8) || circuit.n3 != int(output.size()*8)) return 3;
    auto bw = HandoffHandshake::feed(bob.data(), bob.size(), emp::BOB);
    auto aw = HandoffHandshake::feed(alice.data(), alice.size(), emp::ALICE);
    EmpBlockOwningSpan raw(output.size()*8);
    circuit.compute(raw.data(), bw.data(), aw.data());
    auto decoded = std::make_unique<bool[]>(raw.size());
    emp::ProtocolExecution::prot_exec->reveal(decoded.get(), emp::PUBLIC, raw.data(), static_cast<int>(raw.size()));
    for (size_t i = 0; i < raw.size(); ++i) output[i/8] |= static_cast<uint8_t>(decoded[i] << (i%8));
  } else return 1;
  emp::finalize_plain_prot();
  std::cout.write(reinterpret_cast<const char *>(output.data()), static_cast<std::streamsize>(output.size()));
}
