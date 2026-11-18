#ifndef CONCURRO_HANDOFF_RECORD_HPP
#define CONCURRO_HANDOFF_RECORD_HPP
#include "HandoffHandshake.hpp"
#include <algorithm>
#include <vector>

namespace HandoffRecord {
using HandoffHandshake::feed;
using HandoffHandshake::slice;

/** Encrypt one AES block using the existing Bristol AES-128 key-schedule circuit. */
inline EmpBlockOwningSpan aes(EmpBlockNonOwningSpan key, EmpBlockNonOwningSpan plaintext) {
  emp::BristolFormat circuit(CircuitSynthesis::AES128_FULL_FILEPATH);
  EmpBlockOwningSpan input(256), raw(128), output(128);
  // This pinned circuit takes reversed input bytes and emits MSB-first output bytes.
  for (size_t byte = 0; byte < 16; ++byte) {
    for (size_t bit = 0; bit < 8; ++bit) {
      input[byte*8+bit] = key[(15-byte)*8+bit];
      input[128+byte*8+bit] = plaintext[(15-byte)*8+bit];
    }
  }
  circuit.compute(raw.data(), input.data(), input.data());
  for (size_t byte = 0; byte < 16; ++byte)
    for (size_t bit = 0; bit < 8; ++bit) output[byte*8+bit] = raw[byte*8+7-bit];
  return output;
}

/** Multiply GHASH operands in byte order, adapting DeriveCircuits' NIST multiplier. */
inline EmpBlockOwningSpan multiply(EmpBlockNonOwningSpan x, EmpBlockNonOwningSpan y) {
  const auto zero = emp::CircuitExecution::circ_exec->public_label(false);
  emp::block v[128], z[128];
  std::fill(std::begin(z), std::end(z), zero);
  for (size_t i = 0; i < 128; ++i) v[i] = x[(i / 8) * 8 + 7 - i % 8];
  for (size_t i = 0; i < 128; ++i) {
    const emp::Bit selected(y[(i / 8) * 8 + 7 - i % 8]);
    for (size_t j = 0; j < 128; ++j) z[j] = (emp::Bit(z[j]) ^ (emp::Bit(v[j]) & selected)).bit;
    const emp::Bit carry(v[127]);
    std::move_backward(std::begin(v), std::end(v) - 1, std::end(v));
    v[0] = zero;
    for (const auto j : {0, 1, 2, 7}) v[j] = (emp::Bit(v[j]) ^ carry).bit;
  }
  EmpBlockOwningSpan result(128);
  for (size_t i = 0; i < 128; ++i) result[(i / 8) * 8 + 7 - i % 8] = z[i];
  return result;
}

/** Authenticate arbitrary-length AAD and ciphertext using the existing wire representation. */
inline EmpBlockOwningSpan ghash(EmpBlockNonOwningSpan h, EmpBlockNonOwningSpan aad,
                                EmpBlockNonOwningSpan ciphertext) {
  std::array<uint8_t, 16> zero{};
  auto state = feed(zero.data(), zero.size(), emp::PUBLIC);
  for (const auto &input : {aad, ciphertext}) {
    for (size_t offset = 0; offset < input.size(); offset += 128) {
      auto block = feed(zero.data(), zero.size(), emp::PUBLIC);
      std::copy(input.cbegin() + offset, input.cbegin() + std::min(offset + 128, input.size()), block.begin());
      for (size_t i = 0; i < 128; ++i) block[i] = (emp::Bit(block[i]) ^ emp::Bit(state[i])).bit;
      auto next = multiply(slice(block, 0, 16), h);
      std::copy(next.begin(), next.end(), state.begin());
    }
  }
  std::array<uint8_t, 16> lengths{};
  for (size_t i = 0; i < 8; ++i) {
    lengths[7-i] = static_cast<uint8_t>(uint64_t(aad.size()) >> (i*8));
    lengths[15-i] = static_cast<uint8_t>(uint64_t(ciphertext.size()) >> (i*8));
  }
  auto block = feed(lengths.data(), lengths.size(), emp::PUBLIC);
  for (size_t i = 0; i < 128; ++i) block[i] = (emp::Bit(block[i]) ^ emp::Bit(state[i])).bit;
  return multiply(slice(block, 0, 16), h);
}

/** Encrypt a TLSInnerPlaintext record at a public sequence number without exposing its key. */
inline EmpBlockOwningSpan encrypt(EmpBlockNonOwningSpan key, EmpBlockNonOwningSpan iv,
                                  EmpBlockNonOwningSpan content, uint8_t kind, uint64_t sequence) {
  const size_t length = content.size() / 8 + 1;
  std::array<uint8_t, 5> header{23, 3, 3, static_cast<uint8_t>((length + 16) >> 8),
                              static_cast<uint8_t>(length + 16)};
  auto aad = feed(header.data(), header.size(), emp::PUBLIC);
  auto type = feed(&kind, 1, emp::PUBLIC);
  EmpBlockOwningSpan plaintext(length * 8), ciphertext(length * 8);
  std::copy(content.begin(), content.end(), plaintext.begin());
  std::copy(type.begin(), type.end(), plaintext.begin() + content.size());
  std::array<uint8_t, 16> zero{};
  auto zeros = feed(zero.data(), zero.size(), emp::PUBLIC);
  auto h = aes(key, slice(zeros, 0, 16));
  auto counter = feed(zero.data(), zero.size(), emp::PUBLIC);
  std::copy(iv.begin(), iv.end(), counter.begin());
  for (size_t byte = 0; byte < 8; ++byte) {
    for (size_t bit = 0; bit < 8; ++bit) {
      const auto i = (11 - byte) * 8 + bit;
      counter[i] = (emp::Bit(counter[i]) ^ emp::Bit(bool((sequence >> (byte * 8 + bit)) & 1))).bit;
    }
  }
  const std::array<uint8_t, 4> one{0, 0, 0, 1};
  auto suffix = feed(one.data(), one.size(), emp::PUBLIC);
  std::copy(suffix.begin(), suffix.end(), counter.begin() + 96);
  auto tag_mask = aes(key, slice(counter, 0, 16));
  for (size_t offset = 0; offset < length; offset += 16) {
    const uint32_t value = static_cast<uint32_t>(offset / 16 + 2);
    const std::array<uint8_t, 4> encoded{static_cast<uint8_t>(value >> 24), static_cast<uint8_t>(value >> 16),
                                        static_cast<uint8_t>(value >> 8), static_cast<uint8_t>(value)};
    auto tail = feed(encoded.data(), encoded.size(), emp::PUBLIC);
    std::copy(tail.begin(), tail.end(), counter.begin() + 96);
    auto stream = aes(key, slice(counter, 0, 16));
    for (size_t i = 0; i < std::min(size_t(16), length-offset)*8; ++i)
      ciphertext[offset*8+i] = (emp::Bit(plaintext[offset*8+i]) ^ emp::Bit(stream[i])).bit;
  }
  auto tag = ghash(slice(h, 0, 16), slice(aad, 0, 5), slice(ciphertext, 0, length));
  EmpBlockOwningSpan result((5 + length + 16) * 8);
  std::copy(aad.begin(), aad.end(), result.begin());
  std::copy(ciphertext.begin(), ciphertext.end(), result.begin() + 40);
  for (size_t i = 0; i < 128; ++i) result[40 + ciphertext.size() + i] = (emp::Bit(tag[i]) ^ emp::Bit(tag_mask[i])).bit;
  return result;
}
} // namespace HandoffRecord
#endif
