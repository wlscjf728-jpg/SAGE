#pragma once
#include "aes128.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>
namespace subround {
struct Signature {
    std::array<std::uint64_t,4> words;
    Signature();
    bool operator==(const Signature& other) const;
    bool operator!=(const Signature& other) const { return !(*this==other); }
    bool empty() const;
    unsigned weight() const;
};
struct SignatureHash { std::size_t operator()(const Signature& s) const; };
struct BitSignature { Stage stage; std::size_t bit_index; Signature signature; };
std::vector<BitSignature> generate_signatures(const Aes128& aes, std::size_t plaintext_byte);
std::size_t shifted_bit_index(std::size_t input_bit_index);
}
