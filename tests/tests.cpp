#include "pe_lens.hpp"
#include <algorithm>
#include <functional>
#include <iostream>
#include <stdexcept>
using V=std::vector<std::uint8_t>;
void put16(V&b,std::size_t p,std::uint16_t n){b[p]=static_cast<std::uint8_t>(n);b[p+1]=static_cast<std::uint8_t>(n>>8);}
void put32(V&b,std::size_t p,std::uint32_t n){for(std::size_t i=0;i<4;i++)b[p+i]=static_cast<std::uint8_t>(n>>(i*8));}
V sample(){V b(1024);b[0]='M';b[1]='Z';put32(b,60,128);put32(b,128,0x4550);put16(b,132,0x8664);put16(b,134,1);put16(b,148,240);put16(b,152,0x20b);put16(b,222,0x160);put32(b,260,16);put32(b,304,0x1000);put32(b,308,16);b[392]='.';b[393]='d';b[394]='a';b[395]='t';b[396]='a';put32(b,400,512);put32(b,404,0x1000);put32(b,408,512);put32(b,412,512);put32(b,428,0x40000040);return b;}
bool has(const pe_lens::Report&r,const std::string&rule){return std::any_of(r.findings.begin(),r.findings.end(),[&](const auto&f){return f.rule==rule;});}
void check(bool value){if(!value)throw std::runtime_error("assertion failed");}
void reject(const V&b){try{(void)pe_lens::inspect(b);}catch(const std::runtime_error&){return;}throw std::runtime_error("accepted invalid PE");}
int main(){int pass=0,fail=0;auto test=[&](const char*name,const std::function<void()>&f){try{f();++pass;std::cout<<"PASS "<<name<<'\n';}catch(const std::exception&e){++fail;std::cout<<"FAIL "<<name<<": "<<e.what()<<'\n';}};
test("synthetic PE32+ flags parsed",[]{auto r=pe_lens::inspect(sample());check(r.bits==64&&r.nx_compatible&&r.dynamic_base&&r.high_entropy_va);});
test("DOS signature required",[]{auto b=sample();b[0]=0;reject(b);});
test("PE offset overflow rejected",[]{auto b=sample();put32(b,60,0xffffffff);reject(b);});
test("section budget enforced",[]{auto b=sample();put16(b,134,65535);reject(b);});
test("short optional header rejected",[]{auto b=sample();put16(b,148,2);reject(b);});
test("directory count budget enforced",[]{auto b=sample();put32(b,260,17);reject(b);});
test("section raw overflow rejected",[]{auto b=sample();put32(b,412,0xfffffff0);reject(b);});
test("DEP flag absence is explicit",[]{auto b=sample();put16(b,222,0x60);check(has(pe_lens::inspect(b),"DEP_FLAG_ABSENT"));});
test("ASLR flag absence",[]{auto b=sample();put16(b,222,0x120);check(has(pe_lens::inspect(b),"ASLR_FLAG_ABSENT"));});
test("write-execute section review",[]{auto b=sample();put32(b,428,0xe0000020);check(has(pe_lens::inspect(b),"WRITE_EXECUTE_SECTION"));});
test("stripped relocation inconsistency",[]{auto b=sample();put16(b,150,1);check(has(pe_lens::inspect(b),"ASLR_RELOCS_STRIPPED"));});
test("unbacked relocations remain unconfirmed",[]{auto b=sample();put32(b,304,0x9000);check(has(pe_lens::inspect(b),"RELOCATION_DATA_UNCONFIRMED"));});
test("certificate uses file offset not RVA",[]{auto b=sample();put32(b,296,960);put32(b,300,32);auto r=pe_lens::inspect(b);check(r.certificate_directory_present);check(pe_lens::json(r).find("\"signature_verified\":false")!=std::string::npos);});
test("certificate range cannot exceed file",[]{auto b=sample();put32(b,296,1000);put32(b,300,32);reject(b);});
test("section names JSON escaped",[]{auto b=sample();b[392]='"';b[393]='\n';check(pe_lens::json(pe_lens::inspect(b)).find("\\u000a")!=std::string::npos);});
test("all prefixes bounded",[]{auto b=sample();for(std::size_t i=0;i<b.size();i++){try{(void)pe_lens::inspect(std::span(b.data(),i));}catch(const std::runtime_error&){}}});
test("single byte mutation smoke",[]{auto base=sample();for(std::size_t i=0;i<512;i++){auto b=base;b[i]^=0xff;try{(void)pe_lens::inspect(b);}catch(const std::runtime_error&){}}});
std::cout<<pass<<'/'<<pass+fail<<" passed\n";return fail?1:0;}
