#ifndef CONCURRO_HANDOFF_FIELD_HPP
#define CONCURRO_HANDOFF_FIELD_HPP

#include <emp-tool/emp-tool.h>
#include <openssl/bn.h>
#include <array>
#include <stdexcept>

namespace HandoffField {
using emp::Bit;
using emp::Integer;
constexpr int width = 258;

/** Encode a nonnegative field value with two spare bits for arithmetic. */
inline Integer input(const BIGNUM *value, int party) {
  std::array<bool, width> bits{};
  if (!value || BN_is_negative(value) || BN_num_bits(value) > 256)
    throw std::invalid_argument("field input exceeds 256 bits");
  for (int i = 0; i < 256; ++i) bits[static_cast<size_t>(i)] = BN_is_bit_set(value, i);
  Integer result;
  result.init(bits.data(), 256, party);
  result.resize(width, false);
  return result;
}

/** Add canonical residues modulo a 256-bit prime. */
inline Integer add(const Integer &a, const Integer &b, const Integer &p) {
  auto sum = a + b;
  return sum.select(sum >= p, sum - p);
}

/** Subtract canonical residues modulo a 256-bit prime. */
inline Integer sub(const Integer &a, const Integer &b, const Integer &p) {
  auto difference = a + p - b;
  return difference.select(difference >= p, difference - p);
}

/** Multiply P-256 residues with fixed generalized-Mersenne reduction. */
inline Integer mul(Integer a, Integer b, Integer p) {
  a.resize(513, false);
  b.resize(513, false);
  auto product = a * b;
  // Since 2^256 = 2^224 - 2^192 - 2^96 + 1 (mod p), each fold loses
  // at least 31 high bits. Eight folds leave a value below 2p for a,b < p.
  for (int i = 0; i < 8; ++i) {
    auto low = product;
    low.resize(256, false);
    low.resize(513, false);
    const auto high = product >> 256;
    product = low + (high << 224) - (high << 192) - (high << 96) + high;
  }
  product.resize(width, false);
  product = product.select(product >= p, product - p);
  return product;
}

/** Divide a residue by two in an odd-prime field. */
inline Integer half(const Integer &a, const Integer &p) {
  return a.select(a[0], a + p) >> 1;
}

/** Invert a nonzero residue with a fixed 512-step binary Euclidean circuit. */
inline Integer inverse(const Integer &a, const Integer &p) {
  Integer u = a, v = p, r(width, 1), s(width, 0);
  const Integer one(width, 1), zero(width, 0);
  for (int i = 0; i < 512; ++i) {
    const Bit active = !((u == one) | (v == one) | (u == zero) | (v == zero));
    const Bit both_odd = u[0] & v[0];
    const Bit reduce_u = !u[0] | (v[0] & (u >= v));
    const auto next_u = u.select(both_odd, u - v) >> 1;
    const auto next_v = v.select(both_odd, v - u) >> 1;
    const auto next_r = half(r.select(both_odd, sub(r, s, p)), p);
    const auto next_s = half(s.select(both_odd, sub(s, r, p)), p);
    u = u.select(active & reduce_u, next_u);
    v = v.select(active & !reduce_u, next_v);
    r = r.select(active & reduce_u, next_r);
    s = s.select(active & !reduce_u, next_s);
  }
  return s.select(u == one, r).select(a == zero, zero);
}

/** Check a canonical affine point against the short Weierstrass equation. */
inline Bit on_curve(const Integer &x, const Integer &y, const Integer &p,
                    const Integer &a, const Integer &b) {
  const auto rhs = add(add(mul(mul(x, x, p), x, p), mul(a, x, p), p), b, p);
  return (x < p) & (y < p) & (mul(y, y, p) == rhs);
}

/** Compute the x-coordinate of a finite sum; zero denominators are invalid. */
inline Integer sum_x(const Integer &x1, const Integer &y1, const Integer &x2,
                     const Integer &y2, const Integer &p, const Integer &a,
                     Bit &valid) {
  const Bit same = (x1 == x2) & (y1 == y2);
  const auto square = mul(x1, x1, p);
  const auto double_numerator = add(add(add(square, square, p), square, p), a, p);
  const auto numerator = sub(y2, y1, p).select(same, double_numerator);
  const auto denominator = sub(x2, x1, p).select(same, add(y1, y1, p));
  valid = valid & !(denominator == Integer(width, 0));
  const auto slope = mul(numerator, inverse(denominator, p), p);
  return sub(sub(mul(slope, slope, p), x1, p), x2, p);
}

/** Decode a circuit value for the independent native-arithmetic test oracle. */
inline void reveal(const Integer &value, BIGNUM *out) {
  std::array<bool, width> bits{};
  value.revealBools(bits.data());
  BN_zero(out);
  for (int i = 0; i < width; ++i)
    if (bits[static_cast<size_t>(i)] && !BN_set_bit(out, i)) throw std::runtime_error("BN_set_bit failed");
}
} // namespace HandoffField
#endif
