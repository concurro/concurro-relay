#include "HandoffHandshake.hpp"
#include <cstdlib>
#include <iostream>

/** Generate the protected P-256 and TLS handshake circuit. */
int main(int argc, char **argv) {
  if (argc != 2) { std::cerr << "usage: HandoffDerive OUTPUT_CIRCUIT\n"; return 1; }
  emp::setup_plain_prot(std::getenv("HANDOFF_COUNT_ONLY") == nullptr, argv[1]);
  HandoffHandshake::Input alice{}, bob{};
  HandoffHandshake::evaluate(alice, bob);
  std::cerr << "HANDOFF_GATES total " << emp::CircuitExecution::circ_exec->num_and() << '\n';
  emp::finalize_plain_prot();
}
