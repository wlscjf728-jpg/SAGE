#include "experiment.hpp"
#include <algorithm>
#include <cmath>
#include <random>
#include <set>
namespace subround {
Condition::Condition():visibility(1.0),decoy_ratio(0.0),noise_rate(0.0),rotate_queries(false),stage_filter(-1){}
namespace {
bool getbit(const Signature&s,unsigned i){return ((s.words[i/64]>>(i%64))&1ULL)!=0;}
void flipbit(Signature&s,unsigned i){s.words[i/64]^=(1ULL<<(i%64));}
Signature rotate_signature(const Signature&s){Signature r;for(unsigned i=0;i<255;++i)if(getbit(s,i))r.words[((i+1)%255)/64]|=(1ULL<<(((i+1)%255)%64));return r;}
int stage_class(Stage s){if(s==Stage::InitialAddRoundKey)return 0;if(s==Stage::Round1SubBytes||s==Stage::Round1ShiftRows)return 1;if(s==Stage::Round1MixColumns||s==Stage::Round1AddRoundKey)return 2;return 3;}
}
std::vector<BitSignature> anonymize(const std::vector<BitSignature>& input,std::uint64_t seed,const Condition& c){std::mt19937_64 rng(seed);std::uniform_real_distribution<double> u(0.0,1.0);std::vector<BitSignature> out;std::size_t eligible=0;for(const auto&x:input){if(c.stage_filter>=0&&static_cast<int>(x.stage)!=c.stage_filter)continue;++eligible;if(u(rng)>c.visibility)continue;Signature s=c.rotate_queries?rotate_signature(x.signature):x.signature;for(unsigned i=0;i<255;++i)if(u(rng)<c.noise_rate)flipbit(s,i);out.push_back({Stage::Round2AddRoundKey,0,s});}std::size_t decoys=static_cast<std::size_t>(std::llround(eligible*c.decoy_ratio));for(std::size_t d=0;d<decoys;++d){Signature s;for(unsigned i=0;i<255;++i)if((rng()&1ULL)!=0)flipbit(s,i);out.push_back({Stage::Round2AddRoundKey,0,s});}std::shuffle(out.begin(),out.end(),rng);return out;}
TrialMetrics run_trial(const Block& key,const std::vector<TemplateMap>& templates,std::uint64_t seed,const Condition& c){TrialMetrics m={0,0,0,0,0,0,0,0,0,false,false,Block{{0}}};Aes128 aes(key);for(std::size_t p=0;p<16;++p){auto original=generate_signatures(aes,p);for(const auto&o:original){if(o.stage>Stage::Round1AddRoundKey||o.signature.empty())continue;++m.active_first_round_bits;auto it=templates[p].find(o.signature);if(it==templates[p].end())continue;std::set<int> stages,classes,keys;for(const auto&cand:it->second){stages.insert(static_cast<int>(cand.stage));classes.insert(stage_class(cand.stage));keys.insert(cand.key_byte);}if(stages.size()==1&&*stages.begin()==static_cast<int>(o.stage))++m.exact_stage_unique_bits;if(classes.size()==1&&*classes.begin()==stage_class(o.stage))++m.class_unique_bits;if(keys.size()==1&&*keys.begin()==key[p])++m.key_unique_bits;}auto observed=anonymize(original,seed,c);auto top=top_key_candidates(vote_key_bytes(observed,templates[p]));const unsigned candidate_count=top.empty()?256U:static_cast<unsigned>(top.size());m.total_candidate_count+=candidate_count;m.max_candidate_count=std::max(m.max_candidate_count,candidate_count);if(std::find(top.begin(),top.end(),key[p])!=top.end())++m.true_in_top_bytes;if(top.size()==1){++m.unique_bytes;m.recovered_key[p]=top[0];if(top[0]==key[p])++m.correct_bytes;}}
m.full_key_recovered=(m.correct_bytes==16&&m.unique_bytes==16);if(m.full_key_recovered){Block probe={{0}};probe[0]=0x53;probe[7]=0xa9;m.ciphertext_verified=(Aes128(m.recovered_key).encrypt(probe)==aes.encrypt(probe));}return m;}
}
