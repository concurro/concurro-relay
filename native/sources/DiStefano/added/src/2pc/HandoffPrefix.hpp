#ifndef CONCURRO_HANDOFF_PREFIX_HPP
#define CONCURRO_HANDOFF_PREFIX_HPP
#include "HandoffRecord.hpp"

namespace HandoffPrefix {
using HandoffHandshake::feed;
using HandoffHandshake::slice;
using HandoffHandshake::commitment;

/** Private inputs precede H2, H3, both master-share commitments and the request head. */
inline constexpr size_t fixed_input_bytes = 224;

/** Return the public output size for fragmented headers and one KeyUpdate record. */
inline size_t output_bytes(size_t head_bytes) {
  return 97 + head_bytes + ((head_bytes + 16383) / 16384) * 22 + 27;
}

/** Check the bearer-token alphabet without revealing the credential byte. */
inline emp::Bit token_character(EmpBlockNonOwningSpan bits) {
  emp::Integer value(9, 0);
  for (size_t i = 0; i < 8; ++i) value[i] = emp::Bit(bits[i]);
  auto allowed = ((value >= emp::Integer(9, 'A')) & (value <= emp::Integer(9, 'Z'))) |
                 ((value >= emp::Integer(9, 'a')) & (value <= emp::Integer(9, 'z'))) |
                 ((value >= emp::Integer(9, '0')) & (value <= emp::Integer(9, '9')));
  for (const auto c : {'-', '.', '_', '~', '+', '/', '='}) allowed = allowed | (value == emp::Integer(9, c));
  return allowed;
}

/** Encrypt an agreed credential prefix and privately deliver only c1 and s0 to Bob. */
inline std::vector<uint8_t> evaluate(const std::vector<uint8_t> &alice, const std::vector<uint8_t> &bob,
                                     size_t token_offset, size_t token_bytes) {
  if (alice.size() != bob.size() || alice.size() <= fixed_input_bytes) throw std::runtime_error("invalid prefix input shape");
  const size_t head_bytes = alice.size() - fixed_input_bytes;
  if (!token_bytes || token_offset > head_bytes || token_bytes > head_bytes - token_offset)
    throw std::runtime_error("invalid credential slot");
  auto bw = feed(bob.data(), bob.size(), emp::BOB);
  auto aw = feed(alice.data(), alice.size(), emp::ALICE);
  auto valid = emp::Bit(aw[96*8]) == emp::Bit(bw[96*8]);
  for (size_t i = 96*8+1; i < fixed_input_bytes*8; ++i) valid = valid & (emp::Bit(aw[i]) == emp::Bit(bw[i]));
  for (size_t byte = 0; byte < head_bytes; ++byte) {
    if (byte >= token_offset && byte < token_offset + token_bytes) {
      valid = valid & token_character(slice(aw, fixed_input_bytes + byte, 1));
    } else {
      for (size_t bit = 0; bit < 8; ++bit) {
        const size_t i = (fixed_input_bytes + byte)*8+bit;
        valid = valid & (emp::Bit(aw[i]) == emp::Bit(bw[i]));
      }
    }
  }
  if (std::getenv("HANDOFF_GATE_BREAKDOWN"))
    std::cerr << "HANDOFF_PREFIX_GATES validation " << emp::CircuitExecution::circ_exec->num_and() << '\n';
  auto ac = commitment(slice(aw, 0, 32), slice(aw, 96, 32), "Concurro/Handoff/v1/MS/A");
  auto bc = commitment(slice(bw, 0, 32), slice(aw, 96, 32), "Concurro/Handoff/v1/MS/B");
  for (size_t i = 0; i < 256; ++i) {
    valid = valid & (emp::Bit(ac[i]) == emp::Bit(aw[160*8+i]));
    valid = valid & (emp::Bit(bc[i]) == emp::Bit(aw[192*8+i]));
  }
  if (std::getenv("HANDOFF_GATE_BREAKDOWN"))
    std::cerr << "HANDOFF_PREFIX_GATES share_commitments " << emp::CircuitExecution::circ_exec->num_and() << '\n';
  EmpBlockOwningSpan master(256);
  for (size_t i = 0; i < 256; ++i) master[i] = (emp::Bit(aw[i]) ^ emp::Bit(bw[i])).bit;
  auto h3 = slice(aw, 128, 32);
  EmpBlockNonOwningSpan empty(nullptr, 0);
  EmpBlockOwningSpan c0(256), s0(256), c1(256);
  EmpBlockOwningSpan key0(128), iv0(96), key1(128), iv1(96);
  CircuitSynthesis::hkdf_expand_label_batch(slice(master, 0, 32), {
      {"c ap traffic", h3, c0.data(), 32},
      {"s ap traffic", h3, s0.data(), 32},
  });
  CircuitSynthesis::hkdf_expand_label_batch(slice(c0, 0, 32), {
      {"traffic upd", empty, c1.data(), 32},
      {"key", empty, key0.data(), 16},
      {"iv", empty, iv0.data(), 12},
  });
  CircuitSynthesis::hkdf_expand_label_batch(slice(c1, 0, 32), {
      {"key", empty, key1.data(), 16},
      {"iv", empty, iv1.data(), 12},
  });
  if (std::getenv("HANDOFF_GATE_BREAKDOWN"))
    std::cerr << "HANDOFF_PREFIX_GATES key_schedule " << emp::CircuitExecution::circ_exec->num_and() << '\n';
  EmpBlockOwningSpan key_binding((64+16+12)*8);
  std::copy(aw.begin()+96*8, aw.begin()+160*8, key_binding.begin());
  std::copy(key1.begin(), key1.end(), key_binding.begin()+64*8);
  std::copy(iv1.begin(), iv1.end(), key_binding.begin()+80*8);
  const std::string domain = "Concurro/Handoff/v1/request-key";
  auto domain_wires = feed(reinterpret_cast<const uint8_t *>(domain.data()), domain.size(), emp::PUBLIC);
  EmpBlockOwningSpan message(domain_wires.size()+key_binding.size()), key_commitment(256);
  std::copy(domain_wires.begin(), domain_wires.end(), message.begin());
  std::copy(key_binding.begin(), key_binding.end(), message.begin()+domain_wires.size());
  CircuitSynthesis::sha256(message, key_commitment.data());
  if (std::getenv("HANDOFF_GATE_BREAKDOWN"))
    std::cerr << "HANDOFF_PREFIX_GATES key_commitment " << emp::CircuitExecution::circ_exec->num_and() << '\n';

  EmpBlockOwningSpan output(output_bytes(head_bytes)*8);
  const auto zero = valid ^ valid;
  for (size_t i = 0; i < 8; ++i) output[i] = (i == 0 ? valid : zero).bit;
  std::copy(key_commitment.begin(), key_commitment.end(), output.begin()+8);
  for (size_t i = 0; i < 256; ++i) {
    output[33*8+i] = (emp::Bit(c1[i]) ^ emp::Bit(bw[32*8+i])).bit;
    output[65*8+i] = (emp::Bit(s0[i]) ^ emp::Bit(bw[64*8+i])).bit;
  }
  size_t offset = 97*8;
  uint64_t sequence = 0;
  for (size_t start = 0; start < head_bytes; start += 16384) {
    auto record = HandoffRecord::encrypt(slice(key0, 0, 16), slice(iv0, 0, 12),
                      slice(aw, fixed_input_bytes+start, std::min(size_t(16384), head_bytes-start)), 23, sequence++);
    std::copy(record.begin(), record.end(), output.begin()+offset);
    offset += record.size();
  }
  if (std::getenv("HANDOFF_GATE_BREAKDOWN"))
    std::cerr << "HANDOFF_PREFIX_GATES credential_record " << emp::CircuitExecution::circ_exec->num_and() << '\n';
  const std::array<uint8_t, 5> update{24, 0, 0, 1, 0};
  auto update_wires = feed(update.data(), update.size(), emp::PUBLIC);
  auto update_record = HandoffRecord::encrypt(slice(key0, 0, 16), slice(iv0, 0, 12), slice(update_wires, 0, 5), 22, sequence);
  std::copy(update_record.begin(), update_record.end(), output.begin()+offset);
  if (std::getenv("HANDOFF_GATE_BREAKDOWN"))
    std::cerr << "HANDOFF_PREFIX_GATES key_update_record " << emp::CircuitExecution::circ_exec->num_and() << '\n';
  auto decoded = std::make_unique<bool[]>(output.size());
  for (size_t i = 8; i < output.size(); ++i) output[i] = ((emp::Bit(output[i]) & valid) ^ zero).bit;
  emp::ProtocolExecution::prot_exec->reveal(decoded.get(), emp::PUBLIC, output.data(), static_cast<int>(output.size()));
  std::vector<uint8_t> result(output.size()/8);
  for (size_t i = 0; i < output.size(); ++i) result[i/8] |= static_cast<uint8_t>(decoded[i] << (i%8));
  return result;
}
} // namespace HandoffPrefix
#endif
