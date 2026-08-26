/*
 * Byte-based sparse memory used to construct RVFI memory-dump ELFs.
 *
 * Every entry represents one byte that has explicitly been written:
 *
 *   address -> byte
 *
 * Written zero bytes are retained, so test_elf_mem() distinguishes an
 * unwritten address from an address explicitly written with zero.
 */

#include "mem_dump.h"

#include <cstdint>
#include <map>

namespace sparse_mem_internal {

using ByteMap = std::map<uint64_t, uint8_t>;

ByteMap byte_store;

} // namespace sparse_mem_internal

extern "C" bool test_elf_mem(uint64_t start_addr, uint64_t length)
{
    if (length == 0)
        return false;

    const auto &memory = sparse_mem_internal::byte_store;
    const auto it = memory.lower_bound(start_addr);

    /*
     * lower_bound() guarantees it->first >= start_addr.  Subtraction avoids
     * overflowing start_addr + length when the range reaches UINT64_MAX.
     */
    return it != memory.end() && (it->first - start_addr) < length;
}

extern "C" void write_elf_mem(uint64_t addr, uint8_t data)
{
    sparse_mem_internal::byte_store[addr] = data;
}

extern "C" uint8_t read_elf_mem(uint64_t addr)
{
    const auto &memory = sparse_mem_internal::byte_store;
    const auto it = memory.find(addr);

    return it == memory.end() ? UINT8_C(0) : it->second;
}
