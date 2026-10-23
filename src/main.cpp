#include "pe_lens.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
int main(int argc,char**argv) {
    if(argc==2&&std::string(argv[1])=="--help"){std::cout<<"pe-hardening-lens OWNED_FILE.exe\nStatic metadata only; file is never executed.\n";return 0;}
    if(argc!=2)return 2;
    try {
        auto size=std::filesystem::file_size(argv[1]);if(size>10'000'000)throw std::runtime_error("input exceeds 10 MB");
        std::ifstream input(argv[1],std::ios::binary);if(!input)throw std::runtime_error("cannot open input");
        std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
        if(!input.read(reinterpret_cast<char*>(bytes.data()),static_cast<std::streamsize>(bytes.size())))throw std::runtime_error("cannot read full input");
        std::cout<<pe_lens::json(pe_lens::inspect(bytes));return 0;
    }catch(const std::exception&e){std::cerr<<"Input error: "<<e.what()<<'\n';return 2;}
}
