#include "aes128.hpp"
#include <iostream>
#include <vector>
#include <array>
#include <random>
#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <set>
#include <iomanip>
#include <cmath>

using namespace subround;

namespace {

constexpr std::array<std::uint8_t, 256> kSbox = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};

struct PhysicalCell {
    Stage stage;
    std::size_t bit_index;
};

const std::array<std::uint8_t, 4> kDiffsK4 = {0x01, 0x02, 0x04, 0x08};
const std::array<std::uint8_t, 8> kDiffsK8 = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};
const std::array<std::uint8_t, 10> kDiffsK10 = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
const std::array<std::uint8_t, 12> kDiffsK12 = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8};

bool state_bit(const Block& state, std::size_t bit_index) {
    return ((state[bit_index / 8] >> (bit_index % 8)) & 1U) != 0;
}

unsigned hamming_distance(std::uint32_t a, std::uint32_t b) {
    return static_cast<unsigned>(__builtin_popcount(a ^ b));
}

// Generate template signature directly using S-box lookups (O(1))
std::uint32_t generate_template_sig(std::uint8_t k_cand, Stage s, std::size_t b, const std::vector<std::uint8_t>& diffs) {
    std::uint32_t sig = 0;
    for (std::size_t idx = 0; idx < diffs.size(); ++idx) {
        std::uint8_t diff_val = diffs[idx];
        std::uint8_t val = 0;
        if (s == Stage::InitialAddRoundKey) {
            val = diff_val;
        } else {
            val = kSbox[k_cand] ^ kSbox[k_cand ^ diff_val];
        }
        if ((val >> b) & 1U) {
            sig |= (1U << idx);
        }
    }
    return sig;
}

// Backtracking DFS solver
bool dfs_solve(std::size_t byte_idx, Block& current_key, const std::vector<std::vector<std::uint8_t>>& candidates,
              const Block& p_val, const Block& c_val, std::uint64_t& eval_count) {
    if (byte_idx == 16) {
        eval_count++;
        Aes128 test_aes(current_key);
        return test_aes.encrypt(p_val) == c_val;
    }

    for (std::uint8_t cand : candidates[byte_idx]) {
        current_key[byte_idx] = cand;
        if (dfs_solve(byte_idx + 1, current_key, candidates, p_val, c_val, eval_count)) {
            return true;
        }
    }
    return false;
}

// Bipartite matching constraint checker
bool can_match(std::size_t obs_idx, const std::vector<std::uint32_t>& obs_sigs,
              const std::vector<std::uint32_t>& templates, std::array<int, 8>& template_usage_count,
              unsigned max_dist) {
    if (obs_idx == obs_sigs.size()) {
        return true;
    }

    std::uint32_t obs = obs_sigs[obs_idx];
    for (std::size_t b = 0; b < 8; ++b) {
        if (template_usage_count[b] < 2) {
            if (hamming_distance(obs, templates[b]) <= max_dist) {
                template_usage_count[b]++;
                if (can_match(obs_idx + 1, obs_sigs, templates, template_usage_count, max_dist)) {
                    return true;
                }
                template_usage_count[b]--;
            }
        }
    }
    return false;
}

// Perform trial
bool run_hybrid_trial(unsigned trial_idx, std::uint64_t seed, double visibility, double noise_rate, unsigned K, unsigned max_dist, bool force_one_bit = false) {
    std::mt19937_64 rng(seed + trial_idx);
    
    std::vector<std::uint8_t> diffs;
    if (K == 4) {
        diffs.assign(kDiffsK4.begin(), kDiffsK4.end());
    } else if (K == 8) {
        diffs.assign(kDiffsK8.begin(), kDiffsK8.end());
    } else if (K == 10) {
        diffs.assign(kDiffsK10.begin(), kDiffsK10.end());
    } else if (K == 12) {
        diffs.assign(kDiffsK12.begin(), kDiffsK12.end());
    } else {
        throw std::invalid_argument("K must be 4, 8, 10, or 12");
    }

    Block true_key{{0}};
    for (auto& x : true_key) {
        x = static_cast<std::uint8_t>(rng());
    }
    Aes128 aes(true_key);

    // List all potential first-round subround cells (excluding Initial ARK for force_one_bit)
    std::vector<PhysicalCell> all_eligible_cells;
    std::vector<Stage> byte_local_stages = {Stage::InitialAddRoundKey, Stage::Round1SubBytes, Stage::Round1ShiftRows};
    for (auto stage : byte_local_stages) {
        for (std::size_t b = 0; b < 128; ++b) {
            all_eligible_cells.push_back({stage, b});
        }
    }

    // Apply visibility filter
    std::vector<PhysicalCell> visible_cells;
    if (force_one_bit) {
        // Find exactly 1 S-box/ShiftRows key-dependent cell per byte j
        for (std::size_t j = 0; j < 16; ++j) {
            std::vector<PhysicalCell> byte_cells;
            for (const auto& cell : all_eligible_cells) {
                // Focus ONLY on Round1SubBytes or Round1ShiftRows cells to avoid useless key-independent Initial ARK
                if (cell.stage == Stage::Round1SubBytes || cell.stage == Stage::Round1ShiftRows) {
                    Block p0{{0}};
                    Block p_diff{{0}};
                    p_diff[j] = 1;
                    Aes128 temp_aes(true_key);
                    auto tr0 = temp_aes.trace_encrypt(p0);
                    auto tr_d = temp_aes.trace_encrypt(p_diff);
                    
                    bool toggles_on_j = false;
                    for (std::size_t cp_idx = 0; cp_idx < tr0.size(); ++cp_idx) {
                        if (tr0[cp_idx].stage == cell.stage) {
                            toggles_on_j = (state_bit(tr0[cp_idx].state, cell.bit_index) != state_bit(tr_d[cp_idx].state, cell.bit_index));
                            break;
                        }
                    }
                    if (toggles_on_j) {
                        byte_cells.push_back(cell);
                    }
                }
            }
            if (!byte_cells.empty()) {
                std::uniform_int_distribution<std::size_t> select_dist(0, byte_cells.size() - 1);
                visible_cells.push_back(byte_cells[select_dist(rng)]); // Keep exactly 1 key-dependent cell
            }
        }
    } else {
        for (const auto& cell : all_eligible_cells) {
            std::uniform_real_distribution<double> dist_real(0.0, 1.0);
            if (dist_real(rng) < visibility) {
                visible_cells.push_back(cell);
            }
        }
    }

    if (visible_cells.empty()) {
        std::cerr << "Trial " << trial_idx << ": No visible cells! Skipping." << std::endl;
        return false;
    }

    std::vector<PhysicalCell> shuffled_cells = visible_cells;
    std::shuffle(shuffled_cells.begin(), shuffled_cells.end(), rng);

    // Generate observations under baseline and chosen-plaintext differences
    std::vector<std::vector<std::uint32_t>> observed_sigs(16); // Grouped by active plaintext byte
    
    for (std::size_t j = 0; j < 16; ++j) {
        Block p0{{0}};
        auto tr0 = aes.trace_encrypt(p0);

        std::vector<Block> tr0_states(9);
        for (const auto& cp : tr0) {
            tr0_states[static_cast<int>(cp.stage)] = cp.state;
        }

        std::vector<std::vector<Block>> diff_states(diffs.size(), std::vector<Block>(9));
        for (std::size_t idx = 0; idx < diffs.size(); ++idx) {
            Block p_diff{{0}};
            p_diff[j] = diffs[idx];
            auto tr_diff = aes.trace_encrypt(p_diff);
            for (const auto& cp : tr_diff) {
                diff_states[idx][static_cast<int>(cp.stage)] = cp.state;
            }
        }

        for (std::size_t cell_idx = 0; cell_idx < shuffled_cells.size(); ++cell_idx) {
            const auto& cell = shuffled_cells[cell_idx];

            bool active = false;
            std::uint32_t sig = 0;
            for (std::size_t idx = 0; idx < diffs.size(); ++idx) {
                bool bit0 = state_bit(tr0_states[static_cast<int>(cell.stage)], cell.bit_index);
                bool bit_d = state_bit(diff_states[idx][static_cast<int>(cell.stage)], cell.bit_index);
                if (bit0 != bit_d) {
                    active = true;
                    sig |= (1U << idx);
                }
            }

            if (active && noise_rate > 0.0) {
                std::uniform_real_distribution<double> dist_real(0.0, 1.0);
                for (std::size_t idx = 0; idx < diffs.size(); ++idx) {
                    if (dist_real(rng) < noise_rate) {
                        sig ^= (1U << idx); // Flip bit
                    }
                }
            }

            if (active) {
                observed_sigs[j].push_back(sig);
            }
        }
    }

    std::vector<std::vector<std::uint8_t>> candidates(16);
    
    std::vector<std::uint32_t> init_ark_templates(8);
    for (std::size_t b = 0; b < 8; ++b) {
        init_ark_templates[b] = generate_template_sig(0, Stage::InitialAddRoundKey, b, diffs);
    }

    for (std::size_t j = 0; j < 16; ++j) {
        if (observed_sigs[j].empty()) {
            for (unsigned k = 0; k < 256; ++k) {
                candidates[j].push_back(static_cast<std::uint8_t>(k));
            }
            continue;
        }

        std::vector<std::uint32_t> obs_sb_sr;
        for (auto sig : observed_sigs[j]) {
            bool matches_init = false;
            for (std::size_t b = 0; b < 8; ++b) {
                if (hamming_distance(sig, init_ark_templates[b]) <= max_dist) {
                    matches_init = true;
                    break;
                }
            }
            if (!matches_init) {
                obs_sb_sr.push_back(sig);
            }
        }

        for (unsigned k = 0; k < 256; ++k) {
            std::vector<std::uint32_t> r1_sb_templates(8);
            for (std::size_t b = 0; b < 8; ++b) {
                r1_sb_templates[b] = generate_template_sig(static_cast<std::uint8_t>(k), Stage::Round1SubBytes, b, diffs);
            }

            std::array<int, 8> template_usage_count = {{0}};
            if (can_match(0, obs_sb_sr, r1_sb_templates, template_usage_count, max_dist)) {
                candidates[j].push_back(static_cast<std::uint8_t>(k));
            }
        }

        if (candidates[j].empty()) {
            for (unsigned k = 0; k < 256; ++k) {
                candidates[j].push_back(static_cast<std::uint8_t>(k));
            }
        }
    }

    double total_entropy = 0.0;
    for (std::size_t j = 0; j < 16; ++j) {
        total_entropy += std::log2(candidates[j].size());
    }

    Block p_val{{0x53, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
    Block c_val = aes.encrypt(p_val);

    Block recovered_key{{0}};
    std::uint64_t eval_count = 0;
    bool success = dfs_solve(0, recovered_key, candidates, p_val, c_val, eval_count);

    bool key_matches = (recovered_key == true_key);

    std::cout << std::setw(5) << trial_idx << " | "
              << std::setw(15) << (success && key_matches ? "SUCCESS" : "FAILED") << " | "
              << std::setw(12) << eval_count << " | "
              << std::setw(10) << K << " | "
              << std::setw(12) << total_entropy << " bits | [";
    for (std::size_t j = 0; j < 16; ++j) {
        std::cout << candidates[j].size() << (j == 15 ? "" : ",");
    }
    std::cout << "]" << std::endl;

    return success && key_matches;
}

} // namespace

int main() {
    std::cout << "========================================================================================\n";
    std::cout << "       HYBRID ALGEBRAIC-DIFFERENTIAL SCAN ATTACK EVALUATION (PROTOTOYPE)\n";
    std::cout << "========================================================================================\n";
    std::cout << "Target: AES-128 subround registers (Initial ARK, R1 SB, R1 SR)\n";
    std::cout << "Verification constraints: 1 Plaintext-Ciphertext validation pair\n\n";

    std::uint64_t base_seed = 20260625;
    
    // Experiment 1: Ideal conditions, K = 4 (65 queries)
    std::cout << "--- CONDITION 1: Ideal, 100% Visibility, 0% Noise, K = 4 (65 queries) ---\n";
    std::cout << "Trial |     Status    | Solver Evals | Queries K  | Key Entropy | Candidate Set Sizes\n";
    std::cout << "----------------------------------------------------------------------------------------\n";
    unsigned success_cnt_1 = 0;
    for (unsigned t = 0; t < 10; ++t) {
        if (run_hybrid_trial(t, base_seed, 1.0, 0.0, 4, 0)) {
            success_cnt_1++;
        }
    }
    std::cout << "Condition 1 Success Rate: " << success_cnt_1 << "/10\n\n";

    // Experiment 2: Ideal conditions, K = 8 (129 queries)
    std::cout << "--- CONDITION 2: Ideal, 100% Visibility, 0% Noise, K = 8 (129 queries) ---\n";
    std::cout << "Trial |     Status    | Solver Evals | Queries K  | Key Entropy | Candidate Set Sizes\n";
    std::cout << "----------------------------------------------------------------------------------------\n";
    unsigned success_cnt_2 = 0;
    for (unsigned t = 0; t < 10; ++t) {
        if (run_hybrid_trial(t, base_seed, 1.0, 0.0, 8, 0)) {
            success_cnt_2++;
        }
    }
    std::cout << "Condition 2 Success Rate: " << success_cnt_2 << "/10\n\n";

    // Experiment 3: Partial Visibility, K = 8 (129 queries)
    std::cout << "--- CONDITION 3: 50% Visibility, 0% Noise, K = 8 (129 queries) ---\n";
    std::cout << "Trial |     Status    | Solver Evals | Queries K  | Key Entropy | Candidate Set Sizes\n";
    std::cout << "----------------------------------------------------------------------------------------\n";
    unsigned success_cnt_3 = 0;
    for (unsigned t = 0; t < 10; ++t) {
        if (run_hybrid_trial(t, base_seed, 0.5, 0.0, 8, 0)) {
            success_cnt_3++;
        }
    }
    std::cout << "Condition 3 Success Rate: " << success_cnt_3 << "/10\n\n";

    // Experiment 4: Noise resilient, K = 8 (129 queries)
    std::cout << "--- CONDITION 4: 100% Visibility, 1% Noise, K = 8, d_max = 1 (129 queries) ---\n";
    std::cout << "Trial |     Status    | Solver Evals | Queries K  | Key Entropy | Candidate Set Sizes\n";
    std::cout << "----------------------------------------------------------------------------------------\n";
    unsigned success_cnt_4 = 0;
    for (unsigned t = 0; t < 10; ++t) {
        if (run_hybrid_trial(t, base_seed, 1.0, 0.01, 8, 1)) {
            success_cnt_4++;
        }
    }
    std::cout << "Condition 4 Success Rate: " << success_cnt_4 << "/10\n\n";

    // Experiment 5: Extreme Bottleneck, 1-Bit Visibility per Byte, K = 12 (193 queries)
    std::cout << "--- CONDITION 5: Extreme Bottleneck, 1-Bit Visibility per Byte, K = 12 (193 queries) ---\n";
    std::cout << "Trial |     Status    | Solver Evals | Queries K  | Key Entropy | Candidate Set Sizes\n";
    std::cout << "----------------------------------------------------------------------------------------\n";
    unsigned success_cnt_5 = 0;
    for (unsigned t = 0; t < 10; ++t) {
        if (run_hybrid_trial(t, base_seed, 1.0, 0.0, 12, 0, true)) {
            success_cnt_5++;
        }
    }
    std::cout << "Condition 5 Success Rate: " << success_cnt_5 << "/10\n\n";

    std::cout << "========================================================================================\n";
    return 0;
}
