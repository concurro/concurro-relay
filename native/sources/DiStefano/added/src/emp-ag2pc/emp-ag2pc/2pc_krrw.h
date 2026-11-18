#ifndef EMP_AG2PC_2PC_KRRW_H__
#define EMP_AG2PC_2PC_KRRW_H__
#include "emp-ag2pc/fpre.h"
#include <emp-tool/emp-tool.h>

namespace emp {
/** Authenticated two-party circuit using KRRW half-gate evaluation and validation. */
template <typename T, int threads, template <typename> class OTType,
          bool debug = false>
class C2PCKrrw {
public:
  const static int SSP = 16; // Transmit complete authentication blocks.
  const block MASK = makeBlock(0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL);

  using FpreType = Fpre<T, threads, OTType, debug>;
  FpreType *fpre = nullptr;

  using in_io_type = typename FpreType::in_io_type;

  block *mac = nullptr;
  block *key = nullptr;

  block *preprocess_mac = nullptr;
  block *preprocess_key = nullptr;

  block *sigma_mac = nullptr;
  block *sigma_key = nullptr;

  block *labels = nullptr;

  bool *mask = nullptr;
  BristolFormat *cf;
  T *io;
  int num_ands = 0;
  int party, total_pre;

  uint64_t bandwidth() noexcept { return fpre->bandwidth(); }

  C2PCKrrw(in_io_type io, int party, int tag, BristolFormat *cf) {
    this->party = party;
    this->io = nullptr;

    this->io = FpreType::get_first(io);
    this->cf = cf;

    for (int i = 0; i < cf->num_gate; ++i) {
      if (cf->gates[4 * i + 3] == AND_GATE)
        ++num_ands;
    }

    total_pre = cf->n1 + cf->n2 + num_ands;
    fpre = new Fpre<T, threads, OTType, debug>(io, party, num_ands, tag);

    key = new block[cf->num_wire];
    mac = new block[cf->num_wire];

    preprocess_mac = new block[total_pre];
    preprocess_key = new block[total_pre];

    // sigma values in the paper
    sigma_mac = new block[num_ands];
    sigma_key = new block[num_ands];

    labels = new block[cf->num_wire];

    mask = new bool[cf->n1 + cf->n2];
  }
  ~C2PCKrrw() {
    delete[] key;
    delete[] mac;
    delete[] mask;
    delete[] half_gates;
    delete[] gate_bits;

    delete[] preprocess_mac;
    delete[] preprocess_key;

    delete[] sigma_mac;
    delete[] sigma_key;

    delete[] labels;
    delete fpre;
  }
  PRG prg;
  block (*half_gates)[2] = nullptr;
  uint8_t *gate_bits = nullptr;
  MITCCRH<8> half_gate_hash;

  // not allocation
  block *ANDS_mac = nullptr;
  block *ANDS_key = nullptr;
  void function_independent() {
    if (party == ALICE) {
      prg.random_block(labels, cf->num_wire);
    }
    fpre->refill();

    ANDS_mac = fpre->MAC_res();
    ANDS_key = fpre->KEY_res();

    fpre->independent_ot(preprocess_mac, preprocess_key, total_pre);

    memcpy(key, preprocess_key, (cf->n1 + cf->n2) * sizeof(block));
    memcpy(mac, preprocess_mac, (cf->n1 + cf->n2) * sizeof(block));
    // Flush any pending ops.
    io->flush();
  }

  void function_dependent() {
    int ands = cf->n1 + cf->n2;

    bool *x1 = new bool[num_ands]{};
    bool *y1 = new bool[num_ands]{};
    bool *x2 = new bool[num_ands]{};
    bool *y2 = new bool[num_ands]{};

    for (int i = 0; i < cf->num_gate; ++i) {
      if (cf->gates[4 * i + 3] == AND_GATE) {
        key[cf->gates[4 * i + 2]] = preprocess_key[ands];
        mac[cf->gates[4 * i + 2]] = preprocess_mac[ands];
        ++ands;
      }
    }

    for (int i = 0; i < cf->num_gate; ++i) {
      if (cf->gates[4 * i + 3] == XOR_GATE) {
        key[cf->gates[4 * i + 2]] =
            key[cf->gates[4 * i]] ^ key[cf->gates[4 * i + 1]];
        mac[cf->gates[4 * i + 2]] =
            mac[cf->gates[4 * i]] ^ mac[cf->gates[4 * i + 1]];
      } else if (cf->gates[4 * i + 3] == NOT_GATE) {
        key[cf->gates[4 * i + 2]] = key[cf->gates[4 * i]];
        mac[cf->gates[4 * i + 2]] = mac[cf->gates[4 * i]];
      }
    }

    ands = 0;
    for (int i = 0; i < cf->num_gate; ++i) {
      if (cf->gates[4 * i + 3] == AND_GATE) {
        x1[ands] = getLSB(mac[cf->gates[4 * i]] ^ ANDS_mac[3 * ands]);
        y1[ands] = getLSB(mac[cf->gates[4 * i + 1]] ^ ANDS_mac[3 * ands + 1]);
        ands++;
      }
    }

    if (party == ALICE) {
      io->send_bool(x1, num_ands);
      io->send_bool(y1, num_ands);
      io->flush();
      io->recv_bool(x2, num_ands);
      io->recv_bool(y2, num_ands);
    } else {
      io->recv_bool(x2, num_ands);
      io->recv_bool(y2, num_ands);
      io->send_bool(x1, num_ands);
      io->send_bool(y1, num_ands);
      io->flush();
    }

    for (int i = 0; i < num_ands; ++i) {
      x1[i] = logic_xor(x1[i], x2[i]);
      y1[i] = logic_xor(y1[i], y2[i]);
    }

    ands = 0;

    for (int i = 0; i < cf->num_gate; ++i) {
      if (cf->gates[4 * i + 3] == AND_GATE) {
        sigma_mac[ands] = ANDS_mac[3 * ands + 2];
        sigma_key[ands] = ANDS_key[3 * ands + 2];

        if (x1[ands]) {
          sigma_mac[ands] = sigma_mac[ands] ^ ANDS_mac[3 * ands + 1];
          sigma_key[ands] = sigma_key[ands] ^ ANDS_key[3 * ands + 1];
        }
        if (y1[ands]) {
          sigma_mac[ands] = sigma_mac[ands] ^ ANDS_mac[3 * ands];
          sigma_key[ands] = sigma_key[ands] ^ ANDS_key[3 * ands];
        }
        if (x1[ands] and y1[ands]) {
          if (party == ALICE)
            sigma_key[ands] = sigma_key[ands] ^ fpre->ZDelta();
          else
            sigma_mac[ands] = sigma_mac[ands] ^ fpre->one();
        }

        ands++;
      }
    } // sigma_[] stores the and of input wires to each AND gates

    fpre->free_mac();
    fpre->free_key();

    half_gates = new block[num_ands][2];
    gate_bits = new uint8_t[num_ands];
    half_gate_hash.setS(coin_tossing(prg, io, party));

    ands = 0;
    for (int i = 0; i < cf->num_gate; ++i) {
      const int in0 = cf->gates[4 * i];
      const int in1 = cf->gates[4 * i + 1];
      const int out = cf->gates[4 * i + 2];
      if (cf->gates[4 * i + 3] == XOR_GATE) {
        if (party == ALICE) labels[out] = labels[in0] ^ labels[in1];
      } else if (cf->gates[4 * i + 3] == NOT_GATE) {
        if (party == ALICE) labels[out] = labels[in0] ^ fpre->Delta();
      } else if (cf->gates[4 * i + 3] == AND_GATE) {
        if (party == ALICE) {
          block hashed[4] = {labels[in0], labels[in0] ^ fpre->Delta(),
                             labels[in1], labels[in1] ^ fpre->Delta()};
          half_gate_hash.hash_cir<1, 4>(hashed);
          half_gates[ands][0] = hashed[0] ^ hashed[1] ^ key[in1]
              ^ (select_mask[getLSB(mac[in1])] & fpre->Delta());
          half_gates[ands][1] = hashed[2] ^ hashed[3] ^ labels[in0]
              ^ key[in0] ^ (select_mask[getLSB(mac[in0])] & fpre->Delta());
          labels[out] = hashed[0] ^ hashed[2] ^ sigma_key[ands]
              ^ (select_mask[getLSB(sigma_mac[ands])] & fpre->Delta())
              ^ key[out] ^ (select_mask[getLSB(mac[out])] & fpre->Delta());
          gate_bits[ands] = static_cast<uint8_t>((labels[out][0] >> 1) & 1);
          if (ands == 0 && std::getenv("HANDOFF_TEST_CORRUPT_GATE_BIT"))
            gate_bits[ands] ^= 1;
          if (ands == 0 && std::getenv("HANDOFF_TEST_INVALID_GATE_BIT"))
            gate_bits[ands] = 2;
          io->send_block(half_gates[ands], 2);
          io->send_data(gate_bits + ands, 1);
        } else {
          io->recv_block(half_gates[ands], 2);
          io->recv_data(gate_bits + ands, 1);
          if (gate_bits[ands] > 1)
            error("C2PC KRRW invalid gate bit\n");
        }
        ++ands;
      }
    }

    io->flush();

    // Synthetic regression: show mask shares exposed by uninitialized triples.
    if (party == BOB && std::getenv("HANDOFF_TEST_TRACE_ZERO_TRIPLES")) {
      const auto zero = makeBlock(0, 0);
      int gate = 0;
      for (int i = 0; i < cf->num_gate; ++i) {
        if (cf->gates[4 * i + 3] != AND_GATE) continue;
        if (cmpBlock(ANDS_mac + 3 * gate, &zero, 1) && cmpBlock(ANDS_key + 3 * gate, &zero, 1)) {
          const auto wire = cf->gates[4 * i];
          if (wire >= cf->n1 && wire < cf->n1 + cf->n2)
            std::cerr << "HANDOFF_EXPOSED_MASK " << wire << " " << (x2[gate] ^ getLSB(mac[wire])) << std::endl;
        }
        ++gate;
      }
    }

    delete[] x1;
    delete[] x2;
    delete[] y1;
    delete[] y2;

    block tmp;
    if (party == ALICE) {
      send_partial_block<T, SSP>(io, mac, cf->n1);
      io->flush();

      for (int i = cf->n1; i < cf->n1 + cf->n2; ++i) {
        recv_partial_block<T, SSP>(io, &tmp, 1);
        block ttt = key[i] ^ fpre->Delta();
        ttt = ttt & MASK;
        block mask_key = key[i] & MASK;
        tmp = tmp & MASK;
        if (cmpBlock(&tmp, &mask_key, 1))
          mask[i] = false;
        else if (cmpBlock(&tmp, &ttt, 1))
          mask[i] = true;
        else
          error("C2PC authentication failed\n");
      }
    } else {
      for (int i = 0; i < cf->n1; ++i) {
        recv_partial_block<T, SSP>(io, &tmp, 1);
        block ttt = key[i] ^ fpre->Delta();
        ttt = ttt & MASK;
        tmp = tmp & MASK;
        block mask_key = key[i] & MASK;
        if (cmpBlock(&tmp, &mask_key, 1)) {
          mask[i] = false;
        } else if (cmpBlock(&tmp, &ttt, 1)) {
          mask[i] = true;
        } else
          error("C2PC authentication failed\n");
      }

      send_partial_block<T, SSP>(io, mac + cf->n1, cf->n2);
    }
    io->flush();
  }

  void online(const bool *input, bool *output, bool alice_output = false) {
    uint8_t *mask_input = new uint8_t[cf->num_wire];
    memset(mask_input, 0, cf->num_wire);
    block tmp;
    if (debug) {
      for (int i = 0; i < cf->n1 + cf->n2; ++i)
        check2(mac[i], key[i]);
    }
    if (party == ALICE) {
      for (int i = cf->n1; i < cf->n1 + cf->n2; ++i) {
        mask_input[i] = logic_xor(input[i], getLSB(mac[i]));
        mask_input[i] = logic_xor(mask_input[i], mask[i]);
      }
      io->recv_data(mask_input, cf->n1);
      io->send_data(mask_input + cf->n1, cf->n2);
      for (int i = 0; i < cf->n1 + cf->n2; ++i) {
        tmp = labels[i];
        if (mask_input[i])
          tmp = tmp ^ fpre->Delta();
        io->send_block(&tmp, 1);
      }
      io->flush();
    } else {
      for (int i = 0; i < cf->n1; ++i) {
        mask_input[i] = logic_xor(input[i], getLSB(mac[i]));
        mask_input[i] = logic_xor(mask_input[i], mask[i]);
      }

      io->send_data(mask_input, cf->n1);
      io->flush();
      io->recv_data(mask_input + cf->n1, cf->n2);
      if (std::getenv("HANDOFF_TEST_TRACE_ZERO_TRIPLES")) {
        for (int i = cf->n1; i < cf->n1 + cf->n2; ++i)
          std::cerr << "HANDOFF_MASKED_INPUT " << i << " " << int(mask_input[i]) << std::endl;
      }
      io->recv_block(labels, cf->n1 + cf->n2);
    }
    int ands = 0;
    block *gamma_mac = new block[num_ands];
    block *gamma_key = new block[num_ands];
    uint8_t *and_masks = new uint8_t[num_ands];
    if (party == BOB) {
      for (int i = 0; i < cf->num_gate; ++i) {
        if (cf->gates[4 * i + 3] == XOR_GATE) {
          labels[cf->gates[4 * i + 2]] =
              labels[cf->gates[4 * i]] ^ labels[cf->gates[4 * i + 1]];
          mask_input[cf->gates[4 * i + 2]] = logic_xor(
              mask_input[cf->gates[4 * i]], mask_input[cf->gates[4 * i + 1]]);
        } else if (cf->gates[4 * i + 3] == AND_GATE) {
          const int in0 = cf->gates[4 * i];
          const int in1 = cf->gates[4 * i + 1];
          const int out = cf->gates[4 * i + 2];
          const bool la = mask_input[in0];
          const bool lb = mask_input[in1];
          block hashed[2] = {labels[in0], labels[in1]};
          half_gate_hash.hash_cir<1, 2>(hashed);
          block m = sigma_mac[ands] ^ mac[out]
              ^ (select_mask[la] & mac[in1])
              ^ (select_mask[lb] & mac[in0]);
          labels[out] = hashed[0] ^ hashed[1]
              ^ (select_mask[la] & half_gates[ands][0])
              ^ (select_mask[lb] & (half_gates[ands][1] ^ labels[in0])) ^ m;
          const bool lg = gate_bits[ands] ^ ((labels[out][0] >> 1) & 1);
          mask_input[out] = lg;
          and_masks[ands] = lg;
          if (ands == 0 && std::getenv("HANDOFF_TEST_INVALID_MASKED_BIT"))
            and_masks[ands] = 2;
          const bool public_bit = (la & lb) ^ lg;
          gamma_mac[ands] = m ^ (select_mask[public_bit] & fpre->one());
          gamma_key[ands] = (select_mask[la] & key[in1])
              ^ (select_mask[lb] & key[in0])
              ^ sigma_key[ands] ^ key[out];
          ands++;
        } else {
          mask_input[cf->gates[4 * i + 2]] = not mask_input[cf->gates[4 * i]];
          labels[cf->gates[4 * i + 2]] = labels[cf->gates[4 * i]];
        }
      }
    }
    if (party == ALICE) {
      io->recv_data(and_masks, num_ands);
      for (int i = 0; i < num_ands; ++i)
        if (and_masks[i] > 1)
          error("C2PC KRRW invalid masked bit\n");
      ands = 0;
      for (int i = 0; i < cf->num_gate; ++i) {
        const int in0 = cf->gates[4 * i];
        const int in1 = cf->gates[4 * i + 1];
        const int out = cf->gates[4 * i + 2];
        if (cf->gates[4 * i + 3] == XOR_GATE)
          mask_input[out] = mask_input[in0] ^ mask_input[in1];
        else if (cf->gates[4 * i + 3] == NOT_GATE)
          mask_input[out] = !mask_input[in0];
        else if (cf->gates[4 * i + 3] == AND_GATE) {
          const bool la = mask_input[in0];
          const bool lb = mask_input[in1];
          mask_input[out] = and_masks[ands];
          const bool public_bit = (la & lb) ^ and_masks[ands];
          gamma_mac[ands] = sigma_mac[ands] ^ mac[out]
              ^ (select_mask[la] & mac[in1])
              ^ (select_mask[lb] & mac[in0]);
          gamma_key[ands] = sigma_key[ands] ^ key[out]
              ^ (select_mask[la] & key[in1])
              ^ (select_mask[lb] & key[in0])
              ^ (select_mask[public_bit] & fpre->ZDelta());
          ++ands;
        }
      }
    } else {
      io->send_data(and_masks, num_ands);
      io->flush();
    }
    if (std::getenv("HANDOFF_TEST_CORRUPT_GAMMA_MAC"))
      gamma_mac[0] = gamma_mac[0] ^ makeBlock(0, 0x8000);
    uint8_t *gamma_bits = new uint8_t[num_ands];
    uint8_t *peer_bits = new uint8_t[num_ands];
    for (int i = 0; i < num_ands; ++i)
      gamma_bits[i] = getLSB(gamma_mac[i]);
    char own_digest[Hash::DIGEST_SIZE];
    char peer_digest[Hash::DIGEST_SIZE];
    Hash::hash_once(own_digest, gamma_mac, num_ands * sizeof(block));
    if (party == ALICE) {
      io->send_data(gamma_bits, num_ands);
      io->send_data(own_digest, sizeof(own_digest));
      io->flush();
      io->recv_data(peer_bits, num_ands);
      io->recv_data(peer_digest, sizeof(peer_digest));
    } else {
      io->recv_data(peer_bits, num_ands);
      io->recv_data(peer_digest, sizeof(peer_digest));
      io->send_data(gamma_bits, num_ands);
      io->send_data(own_digest, sizeof(own_digest));
      io->flush();
    }
    for (int i = 0; i < num_ands; ++i) {
      if (peer_bits[i] > 1)
        error("C2PC KRRW invalid validation share\n");
      gamma_key[i] = gamma_key[i]
          ^ (select_mask[peer_bits[i]] & fpre->Delta());
    }
    char expected_digest[Hash::DIGEST_SIZE];
    Hash::hash_once(expected_digest, gamma_key, num_ands * sizeof(block));
    if (memcmp(expected_digest, peer_digest, sizeof(expected_digest)) != 0)
      error("C2PC KRRW validation authentication failed\n");
    for (int i = 0; i < num_ands; ++i)
      if (gamma_bits[i] != peer_bits[i])
        error("C2PC KRRW nonzero gate validation\n");
    if (party == ALICE) {
      send_partial_block<T, SSP>(io, mac + cf->num_wire - cf->n3, cf->n3);
      io->flush();
    }
    delete[] gamma_mac;
    delete[] gamma_key;
    delete[] gamma_bits;
    delete[] peer_bits;
    delete[] and_masks;
    if (party == BOB) {
      bool *o = new bool[cf->n3];
      for (int i = 0; i < cf->n3; ++i) {
        block tmp;
        recv_partial_block<T, SSP>(io, &tmp, 1);
        tmp = tmp & MASK;

        block ttt = key[cf->num_wire - cf->n3 + i] ^ fpre->Delta();
        ttt = ttt & MASK;
        key[cf->num_wire - cf->n3 + i] = key[cf->num_wire - cf->n3 + i] & MASK;

        if (cmpBlock(&tmp, &key[cf->num_wire - cf->n3 + i], 1))
          o[i] = false;
        else if (cmpBlock(&tmp, &ttt, 1))
          o[i] = true;
        else
          error("C2PC authentication failed\n");
      }
      for (int i = 0; i < cf->n3; ++i) {
        output[i] = logic_xor(o[i], mask_input[cf->num_wire - cf->n3 + i]);
        output[i] =
            logic_xor(output[i], getLSB(mac[cf->num_wire - cf->n3 + i]));
      }
      delete[] o;
      if (alice_output) {
        send_partial_block<T, SSP>(io, mac + cf->num_wire - cf->n3, cf->n3);
        send_partial_block<T, SSP>(io, labels + cf->num_wire - cf->n3, cf->n3);
        io->send_data(mask_input + cf->num_wire - cf->n3, cf->n3);
        io->flush();
      }
    } else { // ALICE
      if (alice_output) {
        block *tmp_mac = new block[cf->n3];
        block *tmp_label = new block[cf->n3];
        bool *tmp_mask_input = new bool[cf->n3];
        recv_partial_block<T, SSP>(io, tmp_mac, cf->n3);
        recv_partial_block<T, SSP>(io, tmp_label, cf->n3);
        io->recv_data(tmp_mask_input, cf->n3);
        io->flush();
        for (int i = 0; i < cf->n3; ++i) {
          block tmp = tmp_mac[i];
          tmp = tmp & MASK;

          block ttt = key[cf->num_wire - cf->n3 + i] ^ fpre->Delta();
          ttt = ttt & MASK;
          key[cf->num_wire - cf->n3 + i] =
              key[cf->num_wire - cf->n3 + i] & MASK;

          if (cmpBlock(&tmp, &key[cf->num_wire - cf->n3 + i], 1))
            output[i] = false;
          else if (cmpBlock(&tmp, &ttt, 1))
            output[i] = true;
          else
            error("C2PC authentication failed\n");
          block mask_label = tmp_label[i];
          if (tmp_mask_input[i])
            mask_label = mask_label ^ fpre->Delta();
          mask_label = mask_label & MASK;
          block masked_labels = labels[cf->num_wire - cf->n3 + i] & MASK;
          if (!cmpBlock(&mask_label, &masked_labels, 1))
            error("C2PC authentication failed\n");

          output[i] = logic_xor(output[i], tmp_mask_input[i]);
          output[i] =
              logic_xor(output[i], getLSB(mac[cf->num_wire - cf->n3 + i]));
        }
        delete[] tmp_mac;
        delete[] tmp_label;
        delete[] tmp_mask_input;
      }
    }
    delete[] mask_input;
  }

  void check(block *MAC, block *KEY, bool *r, int length = 1) {
    if (party == ALICE) {
      io->send_data(r, length * 3);
      io->send_block(&fpre->Delta(), 1);
      io->send_block(KEY, length * 3);
      io->flush();
      block DD;
      io->recv_block(&DD, 1);

      for (int i = 0; i < length * 3; ++i) {
        block tmp;
        io->recv_block(&tmp, 1);
        if (r[i])
          tmp = tmp ^ DD;
        if (!cmpBlock(&tmp, &MAC[i], 1))
          cout << i << "\tWRONG ABIT!\n";
      }

    } else {
      bool tmp[3];
      for (int i = 0; i < length; ++i) {
        io->recv_data(tmp, 3);
        bool res =
            (logic_xor(tmp[0], r[3 * i])) and (logic_xor(tmp[1], r[3 * i + 1]));
        if (res != logic_xor(tmp[2], r[3 * i + 2])) {
          cout << i << "\tWRONG!\n";
        }
      }
      block DD;
      io->recv_block(&DD, 1);

      for (int i = 0; i < length * 3; ++i) {
        block tmp;
        io->recv_block(&tmp, 1);
        if (r[i])
          tmp = tmp ^ DD;
        if (!cmpBlock(&tmp, &MAC[i], 1))
          cout << i << "\tWRONG ABIT!\n";
      }
      io->send_block(&fpre->Delta(), 1);
      io->send_block(KEY, length * 3);
    }
    io->flush();
  }

  void check2(block &MAC, block &KEY) {
    if (party == ALICE) {
      io->send_block(&fpre->Delta(), 1);
      io->send_block(&KEY, 1);
      io->flush();
      block DD;
      io->recv_block(&DD, 1);
      for (int i = 0; i < 1; ++i) {
        block tmp;
        io->recv_block(&tmp, 1);
        if (getLSB(MAC))
          tmp = tmp ^ DD;
        if (!cmpBlock(&tmp, &MAC, 1))
          cout << i << "\tWRONG ABIT!2\n";
      }
    } else {
      block DD;
      io->recv_block(&DD, 1);
      for (int i = 0; i < 1; ++i) {
        block tmp;
        io->recv_block(&tmp, 1);
        if (getLSB(MAC))
          tmp = tmp ^ DD;
        if (!cmpBlock(&tmp, &MAC, 1))
          cout << i << "\tWRONG ABIT!2\n";
      }
      io->send_block(&fpre->Delta(), 1);
      io->send_block(&KEY, 1);
    }
    io->flush();
  }

  bool logic_xor(bool a, bool b) { return a != b; }
};
} // namespace emp
#endif // C2PC_H__
