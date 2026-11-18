#include "HandoffHandshake.hpp"
#include <iostream>

/** Evaluate source or serialized handshake circuitry without MPC for fixture diagnosis. */
int main(int argc, char **argv) {
  if (argc != 2) return 1;
  HandoffHandshake::Input alice{}, bob{};
  std::cin.read(reinterpret_cast<char *>(alice.data()), alice.size());
  if (std::cin.gcount() != static_cast<std::streamsize>(alice.size())) return 2;
  std::cin.read(reinterpret_cast<char *>(bob.data()), bob.size());
  if (std::cin.gcount() != static_cast<std::streamsize>(bob.size())) return 2;
  emp::setup_plain_prot(false, "");
  HandoffHandshake::Output output{};
  if (std::string(argv[1]) == "source") {
    output = HandoffHandshake::evaluate(alice, bob);
  } else {
    emp::BristolFormat circuit(argv[1]);
    constexpr auto input_bits = HandoffHandshake::Input{}.size() * 8;
    if (circuit.n1 != input_bits || circuit.n2 != input_bits || circuit.n3 != 1544) return 3;
    auto bw = HandoffHandshake::feed(bob.data(), bob.size(), emp::BOB);
    auto aw = HandoffHandshake::feed(alice.data(), alice.size(), emp::ALICE);
    EmpBlockOwningSpan raw(1544);
    circuit.compute(raw.data(), bw.data(), aw.data());
    std::array<bool, 1544> decoded{};
    emp::ProtocolExecution::prot_exec->reveal(decoded.data(), emp::PUBLIC, raw.data(), 1544);
    for (size_t i = 0; i < decoded.size(); ++i) output[i / 8] |= static_cast<uint8_t>(decoded[i] << (i % 8));
  }
  emp::finalize_plain_prot();
  std::cout.write(reinterpret_cast<const char *>(output.data()), output.size());
}
