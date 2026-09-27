#pragma once
#include "analysis.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>
namespace subround {
struct Condition { double visibility; double decoy_ratio; double noise_rate; bool rotate_queries; int stage_filter; Condition(); };
struct TrialMetrics { unsigned unique_bytes; unsigned correct_bytes; unsigned true_in_top_bytes; unsigned active_first_round_bits; unsigned exact_stage_unique_bits; unsigned class_unique_bits; unsigned key_unique_bits; unsigned total_candidate_count; unsigned max_candidate_count; bool full_key_recovered; bool ciphertext_verified; Block recovered_key; };
std::vector<BitSignature> anonymize(const std::vector<BitSignature>& input,std::uint64_t seed,const Condition& condition);
TrialMetrics run_trial(const Block& key,const std::vector<TemplateMap>& templates,std::uint64_t seed,const Condition& condition);
}
