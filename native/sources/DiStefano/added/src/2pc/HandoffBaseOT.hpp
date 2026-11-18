#ifndef HANDOFF_BASE_OT_HPP
#define HANDOFF_BASE_OT_HPP

#include <cstddef>

/** Send exact bytes through the existing authenticated handoff channel. */
using HandoffSend = void (*)(void *, const void *, size_t);

/** Receive exact bytes through the existing authenticated handoff channel. */
using HandoffReceive = void (*)(void *, void *, size_t);

/** Run malicious MRR base OT as receiver and return 128 selected 128-bit seeds. */
extern "C" void handoff_base_ot_receive(void *context, HandoffSend send,
                                        HandoffReceive receive, const bool *choices,
                                        void *selected);

/** Run malicious MRR base OT as sender and return 128 pairs of 128-bit seeds. */
extern "C" void handoff_base_ot_send(void *context, HandoffSend send,
                                     HandoffReceive receive, void *first,
                                     void *second);

#endif
