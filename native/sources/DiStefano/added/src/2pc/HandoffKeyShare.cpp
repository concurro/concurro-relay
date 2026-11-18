#include "../ssl/Util.hpp"
#include <openssl/ec.h>
#include <openssl/nid.h>
#include <array>
#include <cstring>
#include <iostream>

/** Keep one native P-256 scalar private while producing its public and ECDH contributions. */
int main() {
  auto share = bssl::SSLKeyShare::Create(SSL_CURVE_SECP256R1);
  if (!share) return 1;
  bssl::Array<uint8_t> own;
  if (!Util::generate_public_key(*share, own) || own.size() != 69) return 2;
  std::cout.write(reinterpret_cast<const char *>(own.data()), own.size());
  std::cout.flush();

  std::array<uint8_t, 69> peer_bytes{};
  std::cin.read(reinterpret_cast<char *>(peer_bytes.data()), peer_bytes.size());
  if (std::cin.gcount() != static_cast<std::streamsize>(peer_bytes.size())) return 3;
  bssl::Array<uint8_t> peer;
  if (!peer.Init(peer_bytes.size())) return 3;
  std::memcpy(peer.data(), peer_bytes.data(), peer_bytes.size());

  bssl::UniquePtr<BN_CTX> ctx(BN_CTX_new());
  bssl::UniquePtr<EC_GROUP> group(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
  if (!ctx || !group) return 4;
  bssl::UniquePtr<EC_POINT> joint(EC_POINT_new(group.get()));
  if (!joint || !Util::EC_point_addition(group.get(), &joint, own, peer, ctx.get()) ||
      EC_POINT_is_at_infinity(group.get(), joint.get())) return 4;
  std::array<uint8_t, 65> joint_bytes{};
  if (EC_POINT_point2oct(group.get(), joint.get(), POINT_CONVERSION_UNCOMPRESSED,
                         joint_bytes.data(), joint_bytes.size(), ctx.get()) != joint_bytes.size()) return 4;
  std::cout.write(reinterpret_cast<const char *>(joint_bytes.data()), joint_bytes.size());
  std::cout.flush();

  std::array<uint8_t, 69> server_bytes{};
  std::cin.read(reinterpret_cast<char *>(server_bytes.data()), server_bytes.size());
  if (std::cin.gcount() != static_cast<std::streamsize>(server_bytes.size())) return 5;
  bssl::Array<uint8_t> server, x, y;
  if (!server.Init(server_bytes.size())) return 5;
  std::memcpy(server.data(), server_bytes.data(), server_bytes.size());
  uint8_t alert = 0;
  if (!Util::compute_premaster_secret(*share, server, alert, x, y) ||
      x.size() != 32 || y.size() != 32) return 5;
  std::cout.write(reinterpret_cast<const char *>(x.data()), x.size());
  std::cout.write(reinterpret_cast<const char *>(y.data()), y.size());
  std::cout.flush();
}
