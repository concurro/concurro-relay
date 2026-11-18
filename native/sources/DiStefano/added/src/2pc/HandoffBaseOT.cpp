#include "HandoffBaseOT.hpp"

#include <libOTe/Base/McRosRoy.h>
#include <libOTe/Tools/Coproto.h>
#include <coproto/Socket/Socket.h>
#include <cryptoTools/Crypto/PRNG.h>

#include <array>
#include <coroutine>
#include <cstring>
#include <utility>
#include <vector>

namespace {

/** Adapt the existing authenticated byte channel to coproto's socket API. */
struct HandoffSocket {
  void *context;
  HandoffSend send_bytes;
  HandoffReceive receive_bytes;

  /** Complete one exact byte transfer synchronously on the handoff channel. */
  struct Awaiter {
    HandoffSocket *channel;
    coproto::span<coproto::u8> bytes;
    bool sending;

    bool await_ready() const noexcept { return false; }

    std::coroutine_handle<> await_suspend(std::coroutine_handle<> continuation) {
      if (sending)
        channel->send_bytes(channel->context, bytes.data(), bytes.size());
      else
        channel->receive_bytes(channel->context, bytes.data(), bytes.size());
      return continuation;
    }

    std::pair<coproto::error_code, coproto::u64> await_resume() const noexcept {
      return {{}, bytes.size()};
    }
  };

  Awaiter send(coproto::span<coproto::u8> bytes, macoro::stop_token = {}) {
    return {this, bytes, true};
  }

  Awaiter recv(coproto::span<coproto::u8> bytes, macoro::stop_token = {}) {
    return {this, bytes, false};
  }

  void close() {}
};

/** Open a coproto socket over the handoff channel. */
coproto::Socket make_socket(void *context, HandoffSend send, HandoffReceive receive) {
  return {coproto::make_socket_tag{}, HandoffSocket{context, send, receive}};
}

} // namespace

extern "C" void handoff_base_ot_receive(void *context, HandoffSend send,
                                        HandoffReceive receive, const bool *choices,
                                        void *selected) {
  auto socket = make_socket(context, send, receive);
  osuCrypto::PRNG random(osuCrypto::sysRandomSeed());
  osuCrypto::BitVector choice_bits(128);
  for (size_t i = 0; i < 128; ++i)
    choice_bits[i] = choices[i];
  std::vector<osuCrypto::block> seeds(128);
  osuCrypto::McRosRoy base_ot;
  coproto::sync_wait(base_ot.receive(choice_bits, seeds, random, socket));
  for (size_t i = 0; i < 128; ++i)
    std::memcpy(static_cast<char *>(selected) + i * 16, &seeds[i], 16);
}

extern "C" void handoff_base_ot_send(void *context, HandoffSend send,
                                     HandoffReceive receive, void *first,
                                     void *second) {
  auto socket = make_socket(context, send, receive);
  osuCrypto::PRNG random(osuCrypto::sysRandomSeed());
  std::vector<std::array<osuCrypto::block, 2>> seeds(128);
  osuCrypto::McRosRoy base_ot;
  coproto::sync_wait(base_ot.send(seeds, random, socket));
  for (size_t i = 0; i < 128; ++i) {
    std::memcpy(static_cast<char *>(first) + i * 16, &seeds[i][0], 16);
    std::memcpy(static_cast<char *>(second) + i * 16, &seeds[i][1], 16);
  }
}
