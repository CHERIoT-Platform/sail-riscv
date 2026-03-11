/*
 * mem_dump.cpp – post-execution ELF memory dump (C++ / ELFIO)
 *
 * C++ rewrite of mem_dump.c, structured as closely as possible to
 * riscv/sail-riscv PR#1549 ("Add first party memory model with support
 * for memory dumps").
 *
 * Build requirements:
 *   - g++ with -std=c++17
 *   - ELFIO headers (elfio/elfio.hpp).
 *     Install: sudo apt-get install libelfio-dev
 *     OR:      git clone https://github.com/serge1/ELFIO /opt/elfio
 *              make ELFIO_DIR=/opt/elfio rvfi
 */

/* =========================================================================
 * C++ headers – included FIRST, before any extern "C" declarations.
 *
 * This ordering is required because rts.h → sail.h → gmp.h declares C++
 * stream-operator templates, which are illegal inside an extern "C" block.
 * By including all C++ standard headers here we ensure they are processed
 * in C++ mode before any C-linkage declarations follow.
 * ========================================================================= */
#include "mem.hpp"

#include <elfio/elfio.hpp>

#include <algorithm>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

/* =========================================================================
 * Public interface.
 *
 * mem_dump.h wraps its declaration in  extern "C" { … }  when compiled as
 * C++, so including it here gives mem_dump_elf() C linkage – matching the
 * extern "C" definition at the bottom of this file.
 * ========================================================================= */
#include "mem_dump.h"

/* =========================================================================
 * Sail C runtime symbols – forward-declared with explicit extern "C".
 *
 * We cannot #include "rts.h" or "riscv_platform_impl.h" here because both
 * transitively pull in gmp.h (via sail.h), which declares C++ operator<<
 * templates.  Those templates are invalid inside extern "C" and cause fatal
 * compilation errors.  We therefore declare only the two symbols we need.
 *
 *   read_mem(addr)      – read one byte from Sail's runtime memory model.
 *   rv_htif_tohost      – HTIF tohost address (for the ELF symbol table).
 * ========================================================================= */
extern "C" {
    uint64_t read_mem(uint64_t addr);
    extern uint64_t rv_htif_tohost;
}

using namespace ELFIO;

/* EM_RISCV (243) may not be defined in older elfio/elf_types.hpp. */
#ifndef EM_RISCV
#  define EM_RISCV 243
#endif

/* =========================================================================
 * populate_mem
 *
 * Fill a Memory object from Sail's post-execution runtime state by
 * scanning the address range with read_mem().
 *
 * Serves the same role as the PR's emulator_write_mem() hook: captures
 * the settled memory state (including any self-modifications by
 * jump/branch/store instructions) without needing to intercept every
 * individual write during execution.
 *
 * Only non-zero blocks are inserted into the Memory model to keep it
 * compact.
 * ========================================================================= */
static constexpr uint64_t LOW_MEM_SCAN_SIZE = 0x10000ULL;  /* 64 KiB */

static void populate_mem(Memory &mem, uint64_t base, uint64_t size, int xlen)
{
    const uint64_t addr_size = static_cast<uint64_t>(xlen);

    /* Phase 1: low memory [0, LOW_MEM_SCAN_SIZE) – exception handlers */
    if (base >= LOW_MEM_SCAN_SIZE) {
        for (uint64_t addr = 0; addr < LOW_MEM_SCAN_SIZE;
             addr += Memory::BLOCK_SIZE) {
            uint8_t buf[Memory::BLOCK_SIZE];
            bool nonzero = false;
            for (std::size_t i = 0; i < Memory::BLOCK_SIZE; i++) {
                buf[i] = static_cast<uint8_t>(read_mem(addr + i));
                if (buf[i]) nonzero = true;
            }
            if (nonzero)
                mem.write_bytes(addr, addr_size, buf, Memory::BLOCK_SIZE);
        }
    }

    /* Phase 2: main RAM [base, base+size) */
    for (uint64_t off = 0; off < size; off += Memory::BLOCK_SIZE) {
        uint64_t addr = base + off;
        uint64_t blen = std::min(static_cast<uint64_t>(Memory::BLOCK_SIZE),
                                 size - off);
        uint8_t buf[Memory::BLOCK_SIZE] = {};
        bool nonzero = false;
        for (uint64_t i = 0; i < blen; i++) {
            buf[i] = static_cast<uint8_t>(read_mem(addr + i));
            if (buf[i]) nonzero = true;
        }
        if (nonzero)
            mem.write_bytes(addr, addr_size, buf,
                            static_cast<std::size_t>(blen));
    }
}

/* =========================================================================
 * mem_dump_elf (extern "C")
 *
 * Write the post-execution simulator memory state to an ELF executable.
 *
 * Steps:
 *   1. Populate a Memory object from Sail's runtime (populate_mem).
 *   2. Initialise an ELFIO writer with the correct ELF class (32/64).
 *   3. Iterate the Memory model with for_each_byte, collecting contiguous
 *      byte spans.  For each span, create a SHT_PROGBITS section (set_data)
 *      and back it with a PT_LOAD segment (add_section_index).
 *      This mirrors the PR's dump_memory_to_elf() for_each_byte +
 *      segment-accumulation pattern.
 *   4. Add a .strtab / .symtab pair with the `tohost` symbol so that
 *      load_sail() / lookup_sym() can find it on reload.
 *   5. Save the ELF via ELFIO.
 * ========================================================================= */
extern "C" void mem_dump_elf(const char *filename,
                             uint64_t base, uint64_t size,
                             uint64_t entry_point, int xlen)
{
    /* ------------------------------------------------------------------
     * Step 1: populate Memory from Sail runtime state.
     * ------------------------------------------------------------------ */
    Memory mem;
    populate_mem(mem, base, size, xlen);

    /* ------------------------------------------------------------------
     * Step 2: initialise ELFIO writer.
     * ------------------------------------------------------------------ */
    elfio writer;
    writer.create(xlen == 32 ? ELFCLASS32 : ELFCLASS64, ELFDATA2LSB);
    writer.set_os_abi(ELFOSABI_NONE);
    writer.set_type(ET_EXEC);
    writer.set_machine(EM_RISCV);
    writer.set_entry(entry_point);

    /* ------------------------------------------------------------------
     * Step 3: collect contiguous byte spans from Memory, emit PT_LOAD.
     *
     * Mirrors the PR's for_each_byte + segment-accumulation pattern:
     *
     *   model.memory().for_each_byte(
     *       [&](uint64_t addr, uint8_t value) {
     *           if (in_seg && addr != prev_addr + 1) flush_segment();
     *           if (!in_seg) { seg_start = addr; in_seg = true; }
     *           seg_data.push_back(value);
     *           prev_addr = addr;
     *       }, skip_if_equal_uninitialized = false);
     *   flush_segment();
     *
     * ELFIO note: segment data is stored via sections.  For each span we
     * create a SHT_PROGBITS section (set_data), then attach a PT_LOAD
     * segment to it (add_section_index).  This is the portable ELFIO API
     * that works across all library versions.
     * ------------------------------------------------------------------ */
    std::vector<uint8_t> seg_data;
    uint64_t seg_start = 0;
    uint64_t prev_addr = 0;
    bool     in_seg    = false;
    unsigned seg_idx   = 0;

    auto flush_segment = [&]() {
        if (seg_data.empty())
            return;

        /* Create a PROGBITS section for this contiguous byte span. */
        std::string sec_name = ".seg" + std::to_string(seg_idx++);
        section *sec = writer.sections.add(sec_name);
        sec->set_type(SHT_PROGBITS);
        sec->set_flags(SHF_ALLOC | SHF_EXECINSTR | SHF_WRITE);
        sec->set_address(seg_start);
        sec->set_addr_align(1);
        sec->set_data(reinterpret_cast<const char *>(seg_data.data()),
                      static_cast<Elf_Word>(seg_data.size()));

        /* Back the section with a PT_LOAD segment. */
        segment *pseg = writer.segments.add();
        pseg->set_type(PT_LOAD);
        pseg->set_virtual_address(seg_start);
        pseg->set_physical_address(seg_start);
        pseg->set_flags(PF_X | PF_W | PF_R);
        pseg->set_align(0x1000);
        pseg->add_section_index(sec->get_index(), sec->get_addr_align());

        seg_data.clear();
        in_seg = false;
    };

    mem.for_each_byte([&](uint64_t addr, uint8_t value) {
        if (in_seg && addr != prev_addr + 1) {
            flush_segment();
        }
        if (!in_seg) {
            seg_start = addr;
            in_seg    = true;
        }
        seg_data.push_back(value);
        prev_addr = addr;
    }, /*skip_if_equal_uninitialized=*/false);

    flush_segment();

    /* ------------------------------------------------------------------
     * Step 4: .strtab + .symtab so that load_sail() / lookup_sym() can
     *         find the `tohost` (HTIF exit) address on reload.
     * ------------------------------------------------------------------ */
    section *str_sec = writer.sections.add(".strtab");
    str_sec->set_type(SHT_STRTAB);
    string_section_accessor str_writer(str_sec);

    section *sym_sec = writer.sections.add(".symtab");
    sym_sec->set_type(SHT_SYMTAB);
    sym_sec->set_info(1);   /* index of first global (non-local) symbol */
    sym_sec->set_addr_align(0x4);
    sym_sec->set_entry_size(writer.get_default_entry_size(SHT_SYMTAB));
    sym_sec->set_link(str_sec->get_index());
    symbol_section_accessor sym_writer(writer, sym_sec);

    /* Null symbol at index 0 (required by ELF spec). */
    sym_writer.add_symbol(str_writer, "",
                          /*value=*/0, /*size=*/0,
                          STB_LOCAL, STT_NOTYPE, STV_DEFAULT,
                          SHN_UNDEF);

    /* tohost symbol at index 1 – absolute address. */
    sym_writer.add_symbol(str_writer, "tohost",
                          static_cast<Elf64_Addr>(rv_htif_tohost),
                          /*size=*/0,
                          STB_GLOBAL, STT_NOTYPE, STV_DEFAULT,
                          SHN_ABS);

    /* ------------------------------------------------------------------
     * Step 5: save to file.
     * ------------------------------------------------------------------ */
    if (!writer.save(filename)) {
        fprintf(stderr, "mem_dump: failed to save ELF to '%s'\n", filename);
        return;
    }

    fprintf(stderr,
            "mem_dump: wrote ELF%d with %u PT_LOAD segment(s) to '%s' "
            "(entry=0x%" PRIx64 ", tohost=0x%" PRIx64 ")\n",
            xlen,
            static_cast<unsigned>(writer.segments.size()),
            filename,
            entry_point,
            static_cast<uint64_t>(rv_htif_tohost));
}
