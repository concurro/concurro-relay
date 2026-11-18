#include "HandoffField.hpp"
#include <openssl/ec.h>
#include <openssl/nid.h>
#include <openssl/sha.h>
#include <array>
#include <chrono>
#include <iostream>

/** Compare fixed-shape circuit arithmetic with native P-256 field/point operations. */
int main(int argc, char **argv) {
  using namespace HandoffField;
  const bool record = argc == 2;
  emp::setup_plain_prot(record, record ? argv[1] : "");
  bssl::UniquePtr<BN_CTX> ctx(BN_CTX_new());
  bssl::BN_CTXScope scope(ctx.get());
  bssl::UniquePtr<EC_GROUP> group(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
  auto p = BN_CTX_get(ctx.get()), a = BN_CTX_get(ctx.get()), b = BN_CTX_get(ctx.get());
  auto x1 = BN_CTX_get(ctx.get()), y1 = BN_CTX_get(ctx.get());
  auto x2 = BN_CTX_get(ctx.get()), y2 = BN_CTX_get(ctx.get());
  auto expected = BN_CTX_get(ctx.get()), actual = BN_CTX_get(ctx.get()), scalar = BN_CTX_get(ctx.get());
  if (!scalar || !group || !EC_GROUP_get_curve_GFp(group.get(), p, a, b, ctx.get())) return 1;
  const auto prime = input(p, emp::PUBLIC), ca = input(a, emp::PUBLIC), cb = input(b, emp::PUBLIC);
  bssl::UniquePtr<EC_POINT> first(EC_POINT_new(group.get())), second(EC_POINT_new(group.get())), sum(EC_POINT_new(group.get()));
  const auto started = std::chrono::steady_clock::now();
  for (int i = 0; i < (record ? 1 : 14); ++i) {
    if (!BN_rand_range_ex(scalar, 1, p) || !EC_POINT_mul(group.get(), first.get(), scalar, nullptr, nullptr, ctx.get()) ||
        !BN_rand_range_ex(scalar, 1, p) || !EC_POINT_mul(group.get(), second.get(), scalar, nullptr, nullptr, ctx.get())) return 1;
    if (i == 1 && !EC_POINT_copy(second.get(), first.get())) return 1;
    if (i == 2 && (!EC_POINT_copy(second.get(), first.get()) || !EC_POINT_invert(group.get(), second.get(), ctx.get()))) return 1;
    if (!EC_POINT_get_affine_coordinates_GFp(group.get(), first.get(), x1, y1, ctx.get()) ||
        !EC_POINT_get_affine_coordinates_GFp(group.get(), second.get(), x2, y2, ctx.get())) return 1;
    if (i == 12 && !BN_copy(x1, p)) return 1;
    if (i == 13) { BN_zero(x1); BN_zero(y1); }
    // Feed Bob first, matching the existing Bristol circuit convention.
    const auto bx = input(x2, emp::BOB), by = input(y2, emp::BOB);
    const auto ax = input(x1, emp::ALICE), ay = input(y1, emp::ALICE);
    Bit valid = on_curve(ax, ay, prime, ca, cb) & on_curve(bx, by, prime, ca, cb);
    const auto result = sum_x(ax, ay, bx, by, prime, ca, valid);
    const bool accepted = valid.reveal<bool>();
    reveal(result, actual);
    if (i >= 12) {
      if (accepted) return 5;
      continue;
    }
    if (!EC_POINT_add(group.get(), sum.get(), first.get(), second.get(), ctx.get())) return 1;
    const bool infinity = EC_POINT_is_at_infinity(group.get(), sum.get());
    if (accepted == infinity) return 2;
    if (!infinity && (!EC_POINT_get_affine_coordinates_GFp(group.get(), sum.get(), expected, nullptr, ctx.get()) || BN_cmp(expected, actual))) return 3;
    if (!record) {
      // Check zero, one and p-1 in addition to random inverse operands.
      if (i < 3 && (!BN_set_word(x1, static_cast<BN_ULONG>(i == 2 ? 1 : i)) || (i == 2 && !BN_sub(x1, p, x1)))) return 1;
      reveal(inverse(input(x1, emp::ALICE), prime), actual);
      if (BN_is_zero(x1)) { if (!BN_is_zero(actual)) return 4; }
      else if (!BN_mod_inverse(expected, x1, p, ctx.get()) || BN_cmp(expected, actual)) return 4;
    }
  }
  if (!record) {
    for (int i = 0; i < 5; ++i) {
      if (i < 3 ? !BN_set_word(x1, static_cast<BN_ULONG>(i)) :
          !BN_copy(x1, p) || !BN_sub_word(x1, static_cast<BN_ULONG>(5 - i))) return 6;
      for (int j = 0; j < 5; ++j) {
        if (j < 3 ? !BN_set_word(x2, static_cast<BN_ULONG>(j)) :
            !BN_copy(x2, p) || !BN_sub_word(x2, static_cast<BN_ULONG>(5 - j))) return 6;
        if (!BN_mod_mul(expected, x1, x2, p, ctx.get())) return 6;
        reveal(mul(input(x1, emp::ALICE), input(x2, emp::BOB), prime), actual);
        if (BN_cmp(expected, actual)) return 6;
      }
    }
    for (int i = 0; i < 256; ++i) {
      std::array<uint8_t, 8> seed{};
      std::array<uint8_t, SHA256_DIGEST_LENGTH> digest{};
      seed[1] = static_cast<uint8_t>(i);
      seed[0] = 0xa1;
      SHA256(seed.data(), seed.size(), digest.data());
      if (!BN_bin2bn(digest.data(), digest.size(), x1) || !BN_nnmod(x1, x1, p, ctx.get())) return 7;
      seed[0] = 0xb2;
      SHA256(seed.data(), seed.size(), digest.data());
      if (!BN_bin2bn(digest.data(), digest.size(), x2) || !BN_nnmod(x2, x2, p, ctx.get()) ||
          !BN_mod_mul(expected, x1, x2, p, ctx.get())) return 7;
      reveal(mul(input(x1, emp::ALICE), input(x2, emp::BOB), prime), actual);
      if (BN_cmp(expected, actual)) return 7;
    }
  }
  emp::finalize_plain_prot();
  std::cout << "HANDOFF_FIELD ok seconds=" << std::chrono::duration<double>(std::chrono::steady_clock::now()-started).count() << '\n';
}
