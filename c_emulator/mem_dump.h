#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Return true when at least one byte in
 * [start_addr, start_addr + length) has previously been written.
 *
 * A zero length always returns false.  A byte explicitly written with value
 * zero still counts as written.
 */
bool test_elf_mem(uint64_t start_addr, uint64_t length);

/* Write one byte to the specified address. */
void write_elf_mem(uint64_t addr, uint8_t data);

/* Read one byte.  An address that has never been written returns zero. */
uint8_t read_elf_mem(uint64_t addr);

/*
 * Dump every byte that has been written to an ELF file.
 *
 * Consecutive addresses are combined into one PT_LOAD segment.  Disjoint
 * address ranges are emitted as separate PT_LOAD segments.
 *
 * xlen must be either 32 or 64.  The function returns true on success.
 */
bool dump_elf_mem(const char *filename, uint64_t entry_point, int xlen);

#ifdef __cplusplus
}
#endif
