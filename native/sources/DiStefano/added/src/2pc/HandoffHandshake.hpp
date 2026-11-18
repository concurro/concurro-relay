#ifndef CONCURRO_HANDOFF_HANDSHAKE_HPP
#define CONCURRO_HANDOFF_HANDSHAKE_HPP

#include "CircuitSynthesis.hpp"
#include "HandoffField.hpp"
#include <openssl/ec.h>
#include <openssl/nid.h>
#include <openssl/sha.h>
#include <array>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>

namespace HandoffHandshake {
#ifdef HANDOFF_ARITHMETIC_SHARES
/** Per-party bytes: canonical additive x share, H2, MS mask, and handshake-key masks. */
using Input = std::array<uint8_t, 160>;
constexpr size_t point_input_bytes = 32;
#else
/** Per-party bytes: affine x/y, H2, master-share mask and handshake-key masks. */
using Input = std::array<uint8_t, 192>;
constexpr size_t point_input_bytes = 64;
#endif
/** Valid flag, Bob-masked CHTS/SHTS, masked MS, master-share and handshake-key commitments. */
using Output = std::array<uint8_t, 193>;

/** Feed byte-oriented input using the circuit library's little-bit byte convention. */
inline EmpBlockOwningSpan feed(const uint8_t *bytes, size_t length, int party) {
  auto bits = std::make_unique<bool[]>(length * 8);
  for (size_t i = 0; i < length * 8; ++i) bits[i] = (bytes[i / 8] >> (i % 8)) & 1;
  EmpBlockOwningSpan wires(length * 8);
  emp::ProtocolExecution::prot_exec->feed(wires.data(), party, bits.get(), static_cast<int>(length * 8));
  return wires;
}

/** Select a byte-aligned view of an existing wire buffer. */
inline EmpBlockNonOwningSpan slice(EmpBlockOwningSpan &wires, size_t offset, size_t length) {
  return {wires.data() + offset * 8, length * 8};
}

/** Interpret 32 network-order bytes as an unsigned field integer. */
inline emp::Integer field(EmpBlockNonOwningSpan bytes) {
  emp::Integer value(HandoffField::width, 0);
  for (size_t i = 0; i < 256; ++i) value[i] = emp::Bit(bytes[(31 - i / 8) * 8 + i % 8]);
  return value;
}

/** Expand a TLS 1.3 label while keeping the result inside the circuit. */
inline EmpBlockOwningSpan expand(EmpBlockNonOwningSpan key, const std::string &label,
                                EmpBlockNonOwningSpan context, unsigned bytes = 32) {
  EmpBlockOwningSpan result(bytes * 8);
  CircuitSynthesis::hkdf_expand_label(key, label, context, result.data(), bytes);
  return result;
}

/** Hash a session-bound, domain-separated commitment to a private master-secret share. */
inline EmpBlockOwningSpan commitment(EmpBlockNonOwningSpan share, EmpBlockNonOwningSpan h2,
                                    const std::string &domain) {
  auto prefix = feed(reinterpret_cast<const uint8_t *>(domain.data()), domain.size(), emp::PUBLIC);
  EmpBlockOwningSpan message(prefix.size() + h2.size() + share.size()), result(256);
  std::copy(prefix.begin(), prefix.end(), message.begin());
  std::copy(h2.begin(), h2.end(), message.begin() + prefix.size());
  std::copy(share.begin(), share.end(), message.begin() + prefix.size() + h2.size());
  CircuitSynthesis::sha256(message, result.data());
  return result;
}

/** Derive TLS handshake material without revealing the ECDH or master secret. */
inline Output evaluate(const Input &alice, const Input &bob) {
  constexpr size_t h2_offset = point_input_bytes;
  constexpr size_t master_mask_offset = h2_offset + 32;
  constexpr size_t handshake_mask_offset = master_mask_offset + 32;
  // All private inputs precede computation; EMP's evaluator expects Bob's block first.
  auto bw = feed(bob.data(), bob.size(), emp::BOB);
  auto aw = feed(alice.data(), alice.size(), emp::ALICE);
  if (std::getenv("HANDOFF_GATE_BREAKDOWN"))
    std::cerr << "HANDOFF_GATES inputs " << emp::CircuitExecution::circ_exec->num_and() << '\n';
  const auto ax = field(slice(aw, 0, 32)), bx = field(slice(bw, 0, 32));
#ifndef HANDOFF_ARITHMETIC_SHARES
  const auto ay = field(slice(aw, 32, 32)), by = field(slice(bw, 32, 32));
#endif
  bssl::UniquePtr<BN_CTX> ctx(BN_CTX_new());
  bssl::BN_CTXScope scope(ctx.get());
  bssl::UniquePtr<EC_GROUP> group(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
  auto p = BN_CTX_get(ctx.get());
#ifdef HANDOFF_ARITHMETIC_SHARES
  if (!p || !group || !EC_GROUP_get_curve_GFp(group.get(), p, nullptr, nullptr, ctx.get()))
    throw std::runtime_error("P-256 constants unavailable");
#else
  auto a = BN_CTX_get(ctx.get()), b = BN_CTX_get(ctx.get());
  if (!b || !group || !EC_GROUP_get_curve_GFp(group.get(), p, a, b, ctx.get()))
    throw std::runtime_error("P-256 constants unavailable");
#endif
  const auto prime = HandoffField::input(p, emp::PUBLIC);
#ifndef HANDOFF_ARITHMETIC_SHARES
  const auto ca = HandoffField::input(a, emp::PUBLIC), cb = HandoffField::input(b, emp::PUBLIC);
#endif
#ifdef HANDOFF_ARITHMETIC_SHARES
  emp::Bit valid = (ax < prime) & (bx < prime);
#else
  emp::Bit valid = HandoffField::on_curve(ax, ay, prime, ca, cb) & HandoffField::on_curve(bx, by, prime, ca, cb);
#endif
  for (size_t i = h2_offset * 8; i < (h2_offset + 32) * 8; ++i) valid = valid & (emp::Bit(aw[i]) == emp::Bit(bw[i]));
  if (std::getenv("HANDOFF_GATE_BREAKDOWN"))
    std::cerr << "HANDOFF_GATES on_curve_and_h2 " << emp::CircuitExecution::circ_exec->num_and() << '\n';
#ifdef HANDOFF_ARITHMETIC_SHARES
  const auto x = HandoffField::add(ax, bx, prime);
#else
  const auto x = HandoffField::sum_x(ax, ay, bx, by, prime, ca, valid);
#endif
  if (std::getenv("HANDOFF_GATE_BREAKDOWN"))
    std::cerr << "HANDOFF_GATES point_sum " << emp::CircuitExecution::circ_exec->num_and() << '\n';
  EmpBlockOwningSpan dhe(256);
  for (size_t i = 0; i < 256; ++i) dhe[(31 - i / 8) * 8 + i % 8] = x[i].bit;

  std::array<uint8_t, 32> zeros{}, empty_hash{};
  SHA256(nullptr, 0, empty_hash.data());
  auto zero = feed(zeros.data(), zeros.size(), emp::PUBLIC);
  auto h0 = feed(empty_hash.data(), empty_hash.size(), emp::PUBLIC);
  auto h2 = slice(aw, h2_offset, 32);
  EmpBlockOwningSpan early(256), hs(256), ms(256);
  CircuitSynthesis::hkdf_extract(zero, zero, early.data());
  auto des = expand(slice(early, 0, 32), "derived", slice(h0, 0, 32));
  CircuitSynthesis::hkdf_extract(des, dhe, hs.data());
  EmpBlockOwningSpan chts(256), shts(256), dhs(256);
  CircuitSynthesis::hkdf_expand_label_batch(slice(hs, 0, 32), {
      {"c hs traffic", h2, chts.data(), 32},
      {"s hs traffic", h2, shts.data(), 32},
      {"derived", slice(h0, 0, 32), dhs.data(), 32},
  });
  CircuitSynthesis::hkdf_extract(dhs, zero, ms.data());
  if (std::getenv("HANDOFF_GATE_BREAKDOWN"))
    std::cerr << "HANDOFF_GATES hkdf " << emp::CircuitExecution::circ_exec->num_and() << '\n';

  // Alice's share is her mask; Bob removes only his mask from the public value.
  EmpBlockOwningSpan bob_share(256), masked(256);
  for (size_t i = 0; i < 256; ++i) {
    bob_share[i] = (emp::Bit(ms[i]) ^ emp::Bit(aw[master_mask_offset * 8 + i])).bit;
    masked[i] = (emp::Bit(bob_share[i]) ^ emp::Bit(bw[master_mask_offset * 8 + i])).bit;
  }
  EmpBlockOwningSpan handshake_keys(512), masked_chts(256), masked_shts(256);
  std::copy(chts.begin(), chts.end(), handshake_keys.begin());
  std::copy(shts.begin(), shts.end(), handshake_keys.begin() + 256);
  auto hc = commitment(slice(handshake_keys, 0, 64), h2, "Concurro/Handoff/v2/handshake-keys");
  for (size_t i = 0; i < 256; ++i) {
    masked_chts[i] = (emp::Bit(chts[i]) ^ emp::Bit(bw[handshake_mask_offset*8+i])).bit;
    masked_shts[i] = (emp::Bit(shts[i]) ^ emp::Bit(bw[(handshake_mask_offset+32)*8+i])).bit;
  }
  auto ac = commitment(slice(aw, master_mask_offset, 32), h2, "Concurro/Handoff/v1/MS/A");
  auto bc = commitment(slice(bob_share, 0, 32), h2, "Concurro/Handoff/v1/MS/B");
  if (std::getenv("HANDOFF_GATE_BREAKDOWN"))
    std::cerr << "HANDOFF_GATES commitments " << emp::CircuitExecution::circ_exec->num_and() << '\n';
  EmpBlockOwningSpan output(Output{}.size() * 8);
  const auto wired_zero = valid ^ valid;
  for (size_t i = 0; i < 8; ++i) output[i] = (i == 0 ? valid : wired_zero).bit;
  size_t offset = 8;
  for (auto *value : {&masked_chts, &masked_shts, &masked, &ac, &bc, &hc}) {
    for (size_t i = 0; i < value->size(); ++i) output[offset++] = (emp::Bit((*value)[i]) & valid).bit;
  }
  std::array<bool, Output{}.size() * 8> decoded{};
  emp::ProtocolExecution::prot_exec->reveal(decoded.data(), emp::PUBLIC, output.data(), static_cast<int>(output.size()));
  Output result{};
  for (size_t i = 0; i < decoded.size(); ++i) result[i / 8] |= static_cast<uint8_t>(decoded[i] << (i % 8));
  return result;
}
} // namespace HandoffHandshake
#endif
