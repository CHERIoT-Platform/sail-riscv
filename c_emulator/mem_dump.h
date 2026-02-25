#pragma once

#include <stdint.h>

/*
 * Write the current simulator memory state to an ELF core file.
 *
 * Based on the memory dump approach from riscv/sail-riscv PR#1549.
 * Creates a minimal ELF64 core file with a single PT_LOAD segment
 * covering the RAM region [base, base+size).
 *
 * filename: Output file path.
 * base:     Start address of the RAM region.
 * size:     Size of the RAM region in bytes.
 */
void mem_dump_elf(const char *filename, uint64_t base, uint64_t size);
