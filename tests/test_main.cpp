#include "aes128.hpp"
#include "analysis.hpp"
#include "signature.hpp"
#include "experiment.hpp"
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
using namespace subround;
namespace {
void require(bool c,const std::string&m){if(!c)throw std::runtime_error(m);}
void test_fips197_known_answer(){
 const Block key={{0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f}};
 const Block p={{0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff}};
 const Block e={{0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a}};
 require(Aes128(key).encrypt(p)==e,"FIPS-197 ciphertext mismatch");std::cout<<"PASS fips197_known_answer\n";
}
void test_checkpoint_sequence(){Block z={{0}};auto t=Aes128(z).trace_encrypt(z);require(t.size()==9,"nine checkpoints");require(t[0].stage==Stage::InitialAddRoundKey,"first checkpoint");require(t[8].stage==Stage::Round2AddRoundKey,"last checkpoint");std::cout<<"PASS checkpoint_sequence\n";}
const BitSignature& find_sig(const std::vector<BitSignature>& all,Stage stage,std::size_t bit){for(const auto& x:all)if(x.stage==stage&&x.bit_index==bit)return x;throw std::runtime_error("signature not found");}
void test_signature_equivalences(){Block key={{0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c}};Aes128 aes(key);auto a=generate_signatures(aes,0);auto b=generate_signatures(aes,0);require(a.size()==9*128,"signature count");require(a[137].signature==b[137].signature,"deterministic signatures");for(std::size_t bit=0;bit<128;++bit){require(find_sig(a,Stage::Round1SubBytes,bit).signature==find_sig(a,Stage::Round1ShiftRows,shifted_bit_index(bit)).signature,"SB/SR permutation equivalence");require(find_sig(a,Stage::Round1MixColumns,bit).signature==find_sig(a,Stage::Round1AddRoundKey,bit).signature,"MC/ARK differential equivalence");}std::cout<<"PASS signature_equivalences\n";}
void test_key_byte_vote(){Block key={{0}};key[0]=0xa7;Aes128 aes(key);auto observed=generate_signatures(aes,0);auto templates=build_first_round_templates(0);auto top=top_key_candidates(vote_key_bytes(observed,templates));require(top.size()==1,"key vote must be unique");require(top[0]==0xa7,"true key byte must win");std::cout<<"PASS key_byte_vote\n";}

void test_anonymous_permutation(){Block key={{0}};key[3]=0x5c;auto original=generate_signatures(Aes128(key),3);Condition c;c.visibility=1.0;c.decoy_ratio=0;c.noise_rate=0;auto shuffled=anonymize(original,123,c);require(shuffled.size()==original.size(),"permutation size");TemplateMap t=build_first_round_templates(3);auto top=top_key_candidates(vote_key_bytes(shuffled,t));require(top.size()==1&&top[0]==0x5c,"anonymous permutation key recovery");c.rotate_queries=true;auto control=anonymize(original,123,c);auto control_top=top_key_candidates(vote_key_bytes(control,t));require(!(control_top.size()==1&&control_top[0]==0x5c),"query-order control must break recovery");std::cout<<"PASS anonymous_permutation\n";}

void test_stage_filter(){Block key={{0}};key[0]=0x91;auto original=generate_signatures(Aes128(key),0);Condition c;c.stage_filter=static_cast<int>(Stage::Round1SubBytes);auto only_sb=anonymize(original,77,c);require(only_sb.size()==128,"stage filter must retain one checkpoint");auto top=top_key_candidates(vote_key_bytes(only_sb,build_first_round_templates(0)));require(top.size()==1&&top[0]==0x91,"single checkpoint must recover key byte");std::cout<<"PASS stage_filter\n";}

void test_uninformative_candidate_size(){Block key={{0}};std::vector<TemplateMap> templates;for(std::size_t byte=0;byte<16;++byte)templates.push_back(build_first_round_templates(byte));Condition c;c.stage_filter=static_cast<int>(Stage::InitialAddRoundKey);auto metrics=run_trial(key,templates,91,c);require(metrics.total_candidate_count==4096,"initial ARK must leave 256 candidates per byte");require(metrics.max_candidate_count==256,"initial ARK maximum candidate count");std::cout<<"PASS uninformative_candidate_size\n";}

void test_diffusion_histogram(){Block key={{0}};auto histogram=diffusion_histogram(Aes128(key));require(histogram[static_cast<int>(Stage::InitialAddRoundKey)][1]==128,"initial ARK activity 1");require(histogram[static_cast<int>(Stage::Round1SubBytes)][1]==128,"round1 SB activity 1");require(histogram[static_cast<int>(Stage::Round1ShiftRows)][1]==128,"round1 SR activity 1");require(histogram[static_cast<int>(Stage::Round1MixColumns)][4]==128,"round1 MC activity 4");require(histogram[static_cast<int>(Stage::Round1AddRoundKey)][4]==128,"round1 ARK activity 4");require(histogram[static_cast<int>(Stage::Round2SubBytes)][4]==128,"round2 SB activity 4");require(histogram[static_cast<int>(Stage::Round2ShiftRows)][4]==128,"round2 SR activity 4");require(histogram[static_cast<int>(Stage::Round2MixColumns)][16]==128,"round2 MC activity 16");require(histogram[static_cast<int>(Stage::Round2AddRoundKey)][16]==128,"round2 ARK activity 16");std::cout<<"PASS diffusion_histogram\n";}
}
int main(){try{test_fips197_known_answer();test_checkpoint_sequence();test_signature_equivalences();test_key_byte_vote();test_anonymous_permutation();test_stage_filter();test_uninformative_candidate_size();test_diffusion_histogram();return 0;}catch(const std::exception&e){std::cerr<<"FAIL "<<e.what()<<'\n';return 1;}}
