#include "signature.hpp"

#include <stdexcept>

namespace subround {

Signature::Signature() : words{{0, 0, 0, 0}} {}

bool Signature::operator==(const Signature& other) const {
    return words == other.words;
}

bool Signature::empty() const {
    return words[0] == 0 && words[1] == 0 && words[2] == 0 && words[3] == 0;
}

unsigned Signature::weight() const {
    unsigned result = 0;
    for (const auto word : words) {
        result += static_cast<unsigned>(__builtin_popcountll(word));
    }
    return result;
}

std::size_t SignatureHash::operator()(const Signature& signature) const {
    std::size_t hash = 1469598103934665603ULL;
    for (const auto word : signature.words) {
        hash ^= static_cast<std::size_t>(word);
        hash *= 1099511628211ULL;
    }
    return hash;
}

namespace {

bool state_bit(const Block& state, std::size_t bit_index) {
    return ((state[bit_index / 8] >> (bit_index % 8)) & 1U) != 0;
}

}  // namespace

std::vector<BitSignature> generate_signatures(const Aes128& aes,
                                              std::size_t plaintext_byte) {
    if (plaintext_byte >= 16) {
        throw std::out_of_range("plaintext byte");
    }

    Block baseline_plaintext{{0}};
    const auto baseline_trace = aes.trace_encrypt(baseline_plaintext);
    std::vector<BitSignature> signatures;
    signatures.reserve(baseline_trace.size() * 128);
    for (const auto& checkpoint : baseline_trace) {
        for (std::size_t bit = 0; bit < 128; ++bit) {
            signatures.push_back({checkpoint.stage, bit, Signature()});
        }
    }

    for (unsigned difference = 1; difference <= 255; ++difference) {
        Block plaintext{{0}};
        plaintext[plaintext_byte] = static_cast<std::uint8_t>(difference);
        const auto trace = aes.trace_encrypt(plaintext);
        for (std::size_t stage = 0; stage < trace.size(); ++stage) {
            for (std::size_t bit = 0; bit < 128; ++bit) {
                if (state_bit(baseline_trace[stage].state, bit) !=
                    state_bit(trace[stage].state, bit)) {
                    signatures[stage * 128 + bit]
                        .signature.words[(difference - 1) / 64] |=
                        (std::uint64_t(1) << ((difference - 1) % 64));
                }
            }
        }
    }
    return signatures;
}

std::size_t shifted_bit_index(std::size_t input_bit_index) {
    if (input_bit_index >= 128) {
        throw std::out_of_range("bit");
    }
    const std::size_t byte = input_bit_index / 8;
    const std::size_t subbit = input_bit_index % 8;
    const std::size_t row = byte % 4;
    const std::size_t column = byte / 4;
    const std::size_t destination_column = (column + 4 - row) % 4;
    return (4 * destination_column + row) * 8 + subbit;
}

}  // namespace subround
