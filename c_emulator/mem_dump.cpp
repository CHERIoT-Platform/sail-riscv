/*
 * ELF dump support for the byte-based sparse memory in mem.cpp.
 */

#include <elfio/elfio.hpp>

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <map>
#include <string>
#include <vector>

#include "mem_dump.h"

extern "C" {
    extern uint64_t rv_htif_tohost;
}

namespace sparse_mem_internal {

using ByteMap = std::map<uint64_t, uint8_t>;

extern ByteMap byte_store;

} // namespace sparse_mem_internal

using namespace ELFIO;

#ifndef EM_RISCV
#define EM_RISCV 243
#endif

extern "C" bool dump_elf_mem(const char *filename,
                             uint64_t entry_point,
                             int xlen,
                             bool have_addata_info,
                             uint32_t addata_offset,
                             uint16_t addata_size)
{
    if (filename == nullptr) {
        std::fprintf(stderr, "mem_dump: output filename is null\n");
        return false;
    }

    if (xlen != 32 && xlen != 64) {
        std::fprintf(stderr, "mem_dump: unsupported XLEN %d\n", xlen);
        return false;
    }

    const auto &memory = sparse_mem_internal::byte_store;

    if (xlen == 32 && !memory.empty() &&
        memory.rbegin()->first > std::numeric_limits<uint32_t>::max()) {
        std::fprintf(stderr,
                     "mem_dump: address 0x%" PRIx64
                     " does not fit in an ELF32 file\n",
                     memory.rbegin()->first);
        return false;
    }

    elfio writer;
    writer.create(xlen == 32 ? ELFCLASS32 : ELFCLASS64, ELFDATA2LSB);
    writer.set_os_abi(ELFOSABI_NONE);
    writer.set_type(ET_EXEC);
    writer.set_machine(EM_RISCV);
    writer.set_entry(entry_point);

    std::vector<uint8_t> segment_data;
    uint64_t segment_start = 0;
    uint64_t previous_addr = 0;
    bool segment_active = false;
    unsigned segment_index = 0;

    auto flush_segment = [&]() {
        if (!segment_active)
            return;

        const std::string section_name =
            ".seg" + std::to_string(segment_index++);

        section *sec = writer.sections.add(section_name);
        sec->set_type(SHT_PROGBITS);
        sec->set_flags(SHF_ALLOC | SHF_EXECINSTR | SHF_WRITE);
        sec->set_address(segment_start);
        sec->set_addr_align(1);
        sec->set_data(reinterpret_cast<const char *>(segment_data.data()),
                      static_cast<Elf_Xword>(segment_data.size()));

        segment *seg = writer.segments.add();
        seg->set_type(PT_LOAD);
        seg->set_virtual_address(segment_start);
        seg->set_physical_address(segment_start);
        seg->set_flags(PF_R | PF_W | PF_X);
        seg->set_align(0x1000);
        seg->add_section_index(sec->get_index(), sec->get_addr_align());

        segment_data.clear();
        segment_active = false;
    };

    for (const auto &[addr, data] : memory) {
        const bool contiguous =
            segment_active &&
            previous_addr != std::numeric_limits<uint64_t>::max() &&
            addr == previous_addr + 1;

        if (segment_active && !contiguous)
            flush_segment();

        if (!segment_active) {
            segment_start = addr;
            segment_active = true;
        }

        segment_data.push_back(data);
        previous_addr = addr;
    }

    flush_segment();

    if (have_addata_info) {
        const uint8_t info[8] = {
            static_cast<uint8_t>(addata_offset),
            static_cast<uint8_t>(addata_offset >> 8),
            static_cast<uint8_t>(addata_offset >> 16),
            static_cast<uint8_t>(addata_offset >> 24),
            static_cast<uint8_t>(addata_size),
            static_cast<uint8_t>(addata_size >> 8),
            0, 0
        };
        section *sec = writer.sections.add(".addata_info");
        sec->set_type(SHT_PROGBITS);
        sec->set_flags(0);
        sec->set_addr_align(4);
        sec->set_data(reinterpret_cast<const char *>(info), sizeof(info));
    }

    section *str_sec = writer.sections.add(".strtab");
    str_sec->set_type(SHT_STRTAB);
    string_section_accessor str_writer(str_sec);

    section *sym_sec = writer.sections.add(".symtab");
    sym_sec->set_type(SHT_SYMTAB);
    sym_sec->set_info(1);
    sym_sec->set_addr_align(4);
    sym_sec->set_entry_size(writer.get_default_entry_size(SHT_SYMTAB));
    sym_sec->set_link(str_sec->get_index());
    symbol_section_accessor sym_writer(writer, sym_sec);

    sym_writer.add_symbol(str_writer, "",
                          0, 0,
                          STB_LOCAL, STT_NOTYPE, STV_DEFAULT,
                          SHN_UNDEF);

    sym_writer.add_symbol(str_writer, "tohost",
                          static_cast<Elf64_Addr>(rv_htif_tohost),
                          0,
                          STB_GLOBAL, STT_NOTYPE, STV_DEFAULT,
                          SHN_ABS);

    if (!writer.save(filename)) {
        std::fprintf(stderr,
                     "mem_dump: failed to save ELF to '%s'\n",
                     filename);
        return false;
    }

    std::fprintf(stderr,
                 "mem_dump: wrote %zu byte(s) in %u PT_LOAD segment(s) "
                 "to '%s' (entry=0x%" PRIx64 ")\n",
                 memory.size(),
                 segment_index,
                 filename,
                 entry_point);

    return true;
}
