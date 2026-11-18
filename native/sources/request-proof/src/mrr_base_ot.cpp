#include "HandoffBaseOT.hpp"

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <sys/socket.h>
#include <unistd.h>

namespace {

/** Write all bytes of one MRR byte-stream segment to the proof connection. */
void send_bytes(void* context, const void* data, size_t size) {
  const int fd = *static_cast<int*>(context);
  const auto* cursor = static_cast<const uint8_t*>(data);
  while (size) {
    const auto written = send(fd, cursor, size, MSG_NOSIGNAL);
    if (written < 0 && errno == EINTR) continue;
    if (written <= 0) throw std::runtime_error("MRR proof socket send failed");
    cursor += written;
    size -= written;
  }
}

/** Read all bytes of one MRR byte-stream segment from the proof connection. */
void receive_bytes(void* context, void* data, size_t size) {
  const int fd = *static_cast<int*>(context);
  auto* cursor = static_cast<uint8_t*>(data);
  while (size) {
    const auto received = recv(fd, cursor, size, 0);
    if (received < 0 && errno == EINTR) continue;
    if (received <= 0) throw std::runtime_error("MRR proof socket receive failed");
    cursor += received;
    size -= received;
  }
}

}  // namespace

/** Run 128 random MRR base OTs as sender and expose the seed pairs to Rust. */
extern "C" int handoff_mrr_send_fd(int fd, void* first, void* second) noexcept {
  try {
    handoff_base_ot_send(&fd, send_bytes, receive_bytes, first, second);
    return 0;
  } catch (...) {
    return -1;
  }
}

/** Run 128 random MRR base OTs as receiver for the supplied KOS choices. */
extern "C" int handoff_mrr_receive_fd(int fd, const bool* choices,
                                       void* selected) noexcept {
  try {
    handoff_base_ot_receive(&fd, send_bytes, receive_bytes, choices, selected);
    return 0;
  } catch (...) {
    return -1;
  }
}
