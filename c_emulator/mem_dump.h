#pragma once

#include <stdint.h>

/*
 * Write the post-execution simulator memory state to an ELF executable file.
 *
 * Based on the memory dump approach from riscv/sail-riscv PR#1549.
 *
 * After all instructions have been executed (including any self-modifications
 * caused by jump/branch/store instructions), this function writes the settled
 * memory contents to an ELF file that can be reloaded and re-executed to
 * reproduce a consistent memory view.
 *
 * The ELF class (32-bit / 64-bit) is chosen to match `xlen` so that the
 * produced file is accepted by both the RV32 and RV64 simulator builds:
 *   xlen == 32  ->  ELFCLASS32 (ELF32 headers, 32-bit addresses)
 *   xlen == 64  ->  ELFCLASS64 (ELF64 headers, 64-bit addresses)
 *
 * Only non-zero blocks of RAM are emitted as PT_LOAD segments, keeping the
 * file compact when most of the address space is unused.  The ELF entry
 * point is set to `entry_point` so the loader knows where execution begins.
 *
 * filename    : Output file path (e.g. "memdump_000000.elf").
 * base        : Physical start address of the RAM region to dump.
 * size        : Size of the RAM region in bytes.
 * entry_point : Address at which re-execution should begin (typically
 *               rv_ram_base, i.e. 0x80000000 in RVFI modes).
 * xlen        : Address width in bits – pass (int)zxlen_val (32 or 64).
 *
 * Implemented in mem_dump.cpp (C++ / ELFIO).  The #ifdef __cplusplus guards
 * give this declaration C linkage when included from C++ translation units,
 * matching the extern "C" definition in mem_dump.cpp.
 */

#ifdef __cplusplus
extern "C" {
#endif

void mem_dump_elf(const char *filename, uint64_t base, uint64_t size,
                  uint64_t entry_point, int xlen);

#ifdef __cplusplus
}
#endif
