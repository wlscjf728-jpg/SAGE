#include "analysis.hpp"
#include <algorithm>
namespace subround {

DiffusionHistogram diffusion_histogram(const Aes128& aes){
 std::array<std::array<unsigned,128>,9> activity={{}};
 for(std::size_t plaintext_byte=0;plaintext_byte<16;++plaintext_byte){
  const auto signatures=generate_signatures(aes,plaintext_byte);
  for(const auto& item:signatures)if(!item.signature.empty())++activity[static_cast<int>(item.stage)][item.bit_index];
 }
 DiffusionHistogram histogram={{}};
 for(std::size_t stage=0;stage<activity.size();++stage)for(const auto count:activity[stage])++histogram[stage][count];
 return histogram;
}

TemplateMap build_first_round_templates(std::size_t pbyte){TemplateMap map;for(unsigned key=0;key<256;++key){Block k={{0}};k[pbyte]=static_cast<std::uint8_t>(key);auto sigs=generate_signatures(Aes128(k),pbyte);for(const auto&s:sigs){if(s.stage>Stage::Round1AddRoundKey||s.signature.empty())continue;map[s.signature].push_back({static_cast<std::uint8_t>(key),s.stage,s.bit_index});}}return map;}
std::array<unsigned,256> vote_key_bytes(const std::vector<BitSignature>& observed,const TemplateMap& templates){std::array<unsigned,256> votes={{0}};for(const auto&o:observed){if(o.signature.empty())continue;auto it=templates.find(o.signature);if(it==templates.end())continue;for(const auto&c:it->second)++votes[c.key_byte];}return votes;}
std::vector<std::uint8_t> top_key_candidates(const std::array<unsigned,256>& votes){unsigned best=*std::max_element(votes.begin(),votes.end());std::vector<std::uint8_t> out;if(best==0)return out;for(unsigned i=0;i<256;++i)if(votes[i]==best)out.push_back(static_cast<std::uint8_t>(i));return out;}
}
