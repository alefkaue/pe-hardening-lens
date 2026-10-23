#include "pe_lens.hpp"
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <stdexcept>
namespace pe_lens {
namespace {
using Bytes = std::span<const std::uint8_t>;
bool fits(Bytes b, std::size_t p, std::size_t n) { return p <= b.size() && n <= b.size()-p; }
std::uint16_t u16(Bytes b, std::size_t p) {
    if (!fits(b,p,2)) throw std::runtime_error("truncated 16-bit field");
    return static_cast<std::uint16_t>(b[p] | (b[p+1]<<8));
}
std::uint32_t u32(Bytes b, std::size_t p) {
    if (!fits(b,p,4)) throw std::runtime_error("truncated 32-bit field");
    std::uint32_t n=0; for(std::size_t i=0;i<4;i++) n |= static_cast<std::uint32_t>(b[p+i]) << (8*i); return n;
}
std::string quote(const std::string& s) {
    std::ostringstream out; out << '"';
    for (const unsigned char c : s) {
        if(c=='"'||c=='\\') out << '\\' << c;
        else if(c<32||c>=127) out << "\\u00" << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(c) << std::dec;
        else out<<c;
    } return out.str()+'"';
}
}
Report inspect(Bytes b) {
    if(b.size()>10'000'000) throw std::runtime_error("input exceeds 10 MB");
    if(!fits(b,0,64)||b[0]!='M'||b[1]!='Z') throw std::runtime_error("DOS header missing or truncated");
    const auto pe=static_cast<std::size_t>(u32(b,60));
    if(!fits(b,pe,24)||u32(b,pe)!=0x00004550) throw std::runtime_error("PE signature/header invalid");
    const auto number=u16(b,pe+6), size=u16(b,pe+20), coff_flags=u16(b,pe+22);
    if(number==0||number>96) throw std::runtime_error("section count outside supported 1..96 budget");
    const auto opt=pe+24;
    if(!fits(b,opt,size)||size<2) throw std::runtime_error("optional header truncated");
    const auto magic=u16(b,opt);
    const unsigned bits=magic==0x10b?32:magic==0x20b?64:0;
    const std::size_t directory_start=bits==32?96:112;
    if(bits==0||size<directory_start) throw std::runtime_error("unsupported or short optional header");
    const auto directories=u32(b,opt+(bits==32?92:108));
    if(directories>16||directories*8>size-directory_start) throw std::runtime_error("data directory count exceeds optional header");
    const auto sections=opt+size;
    if(!fits(b,sections,static_cast<std::size_t>(number)*40)) throw std::runtime_error("section table truncated");
    const auto dll_flags=u16(b,opt+70);
    Report result; result.bits=bits; result.machine=u16(b,pe+4); result.input_bytes=b.size();
    result.dynamic_base=(dll_flags&0x40)!=0;result.nx_compatible=(dll_flags&0x100)!=0;
    result.high_entropy_va=(dll_flags&0x20)!=0;result.cfg_declared=(dll_flags&0x4000)!=0;
    auto add=[&](std::string rule,std::string priority,std::string evidence){result.findings.push_back({std::move(rule),std::move(priority),std::move(evidence)});};
    if(!result.dynamic_base) add("ASLR_FLAG_ABSENT","medium","DYNAMIC_BASE is not declared; actual loader/OS policy was not measured.");
    if(!result.nx_compatible) add("DEP_FLAG_ABSENT","medium","NX_COMPAT is not declared; this is not an exploitation verdict.");
    if(bits==64&&!result.high_entropy_va) add("HIGH_ENTROPY_ABSENT","info","64-bit high-entropy VA flag is not declared.");
    if(bits==32&&result.high_entropy_va) add("HIGH_ENTROPY_ON_PE32","review","High-entropy VA bit is set on a PE32 image; verify packaging intent.");
    if(result.dynamic_base&&(coff_flags&1)!=0) add("ASLR_RELOCS_STRIPPED","review","DYNAMIC_BASE and RELOCS_STRIPPED are both set; review loader behavior.");
    if((result.machine==0x8664&&bits!=64)||(result.machine==0x14c&&bits!=32)) add("MACHINE_OPTIONAL_MISMATCH","review","Machine and optional-header formats disagree.");
    for(unsigned i=0;i<number;i++) {
        const auto p=sections+static_cast<std::size_t>(i)*40;std::string name;
        for(std::size_t j=0;j<8&&b[p+j]!=0;j++) name+=static_cast<char>(b[p+j]);
        Section s{name,u32(b,p+20),u32(b,p+16),u32(b,p+12),u32(b,p+8),u32(b,p+36)};
        if(s.raw_size&&!fits(b,s.raw_offset,s.raw_size)) throw std::runtime_error("section raw range exceeds file");
        if((s.flags&0x20000000u)&&(s.flags&0x80000000u)) add("WRITE_EXECUTE_SECTION","medium","A section declares both write and execute permissions. Review packer/JIT/build context; malware is not inferred.");
        for(const auto& prior:result.sections) {
            const auto start=static_cast<std::uint64_t>(s.raw_offset),end=start+s.raw_size;
            const auto old_start=static_cast<std::uint64_t>(prior.raw_offset),old_end=old_start+prior.raw_size;
            if(s.raw_size&&prior.raw_size&&start<old_end&&old_start<end) add("OVERLAPPING_RAW_SECTIONS","review","Two section raw ranges overlap; inspect before trusting mappings.");
        } result.sections.push_back(s);
    }
    auto directory=[&](unsigned index) {const auto p=opt+directory_start+index*8;return std::pair(u32(b,p),u32(b,p+4));};
    if(directories>4) {
        auto [offset,length]=directory(4);
        result.certificate_directory_present=offset!=0&&length!=0;
        if((offset==0)!=(length==0)) add("CERTIFICATE_DIRECTORY_INCONSISTENT","review","Certificate file offset and size are only partially set.");
        if(result.certificate_directory_present&&!fits(b,offset,length)) throw std::runtime_error("certificate directory exceeds file");
    }
    if(result.dynamic_base) {
        bool backed=false;
        if(directories>5) {
            auto [rva,length]=directory(5);
            for(const auto& s:result.sections) {
                if(length&&rva>=s.rva) {
                    const auto delta=static_cast<std::uint64_t>(rva)-s.rva;
                    if(delta<=s.raw_size&&length<=s.raw_size-delta) backed=true;
                }
            }
        }
        if(!backed) add("RELOCATION_DATA_UNCONFIRMED","review","DYNAMIC_BASE is declared but a file-backed relocation range was not established. Relocation entries were not semantically validated.");
    }
    return result;
}
std::string json(const Report& r) {
    std::ostringstream out;
    out<<"{\"scope\":\"Offline PE metadata inspection; no execution, signature verification or exploitability test\",\"bits\":"<<r.bits<<",\"machine\":"<<r.machine
       <<",\"input_bytes\":"<<r.input_bytes<<",\"dynamic_base\":"<<(r.dynamic_base?"true":"false")<<",\"nx_compatible\":"<<(r.nx_compatible?"true":"false")
       <<",\"cfg_declared\":"<<(r.cfg_declared?"true":"false")<<",\"certificate_directory_present\":"<<(r.certificate_directory_present?"true":"false")<<",\"signature_verified\":false,\"sections\":[";
    for(std::size_t i=0;i<r.sections.size();i++){if(i)out<<',';const auto&s=r.sections[i];out<<"{\"name\":"<<quote(s.name)<<",\"raw_offset\":"<<s.raw_offset<<",\"raw_size\":"<<s.raw_size<<'}';}
    out<<"],\"findings\":[";
    for(std::size_t i=0;i<r.findings.size();i++){if(i)out<<',';const auto&f=r.findings[i];out<<"{\"rule\":"<<quote(f.rule)<<",\"priority\":"<<quote(f.priority)<<",\"evidence\":"<<quote(f.evidence)<<'}';}
    return out.str()+"]}\n";
}
}
