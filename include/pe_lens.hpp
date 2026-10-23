#pragma once
#include <cstdint>
#include <span>
#include <string>
#include <vector>
namespace pe_lens {
struct Finding { std::string rule, priority, evidence; };
struct Section { std::string name; std::uint32_t raw_offset, raw_size, rva, virtual_size, flags; };
struct Report {
    unsigned bits{}; std::uint16_t machine{};
    bool dynamic_base{}, nx_compatible{}, high_entropy_va{}, cfg_declared{}, certificate_directory_present{};
    std::size_t input_bytes{}; std::vector<Section> sections; std::vector<Finding> findings;
};
Report inspect(std::span<const std::uint8_t> bytes);
std::string json(const Report& report);
}
