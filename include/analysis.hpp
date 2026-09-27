#pragma once
#include "signature.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <vector>
namespace subround {
struct Candidate { std::uint8_t key_byte; Stage stage; std::size_t bit_index; };
using DiffusionHistogram=std::array<std::array<unsigned,17>,9>;
DiffusionHistogram diffusion_histogram(const Aes128& aes);
using TemplateMap=std::unordered_map<Signature,std::vector<Candidate>,SignatureHash>;
TemplateMap build_first_round_templates(std::size_t plaintext_byte);
std::array<unsigned,256> vote_key_bytes(const std::vector<BitSignature>& observed,const TemplateMap& templates);
std::vector<std::uint8_t> top_key_candidates(const std::array<unsigned,256>& votes);
}
