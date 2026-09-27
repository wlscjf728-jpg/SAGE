#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace subround {

using Block = std::array<std::uint8_t, 16>;

enum class Stage {
    InitialAddRoundKey,
    Round1SubBytes,
    Round1ShiftRows,
    Round1MixColumns,
    Round1AddRoundKey,
    Round2SubBytes,
    Round2ShiftRows,
    Round2MixColumns,
    Round2AddRoundKey,
};

struct Checkpoint {
    Stage stage;
    Block state;
};

using Trace = std::vector<Checkpoint>;

class Aes128 {
  public:
    explicit Aes128(const Block& key);

    Block encrypt(const Block& plaintext) const;
    Trace trace_encrypt(const Block& plaintext) const;

  private:
    std::array<Block, 11> round_keys_{};
};

std::string stage_name(Stage stage);

}  // namespace subround
