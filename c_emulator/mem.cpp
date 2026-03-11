/*
 * mem.cpp – first-party sparse memory model implementation.
 *
 * Direct C++ port of c_emulator/mem.cpp from riscv/sail-riscv PR#1549
 * ("Add first party memory model with support for memory dumps").
 *
 * Implements the three non-template methods of class Memory (declared in
 * mem.hpp).  The template method for_each_byte is defined inline in the
 * header because the C++ standard requires template bodies to be visible
 * at instantiation sites.
 */

#include "mem.hpp"

#include <algorithm>
#include <cstdint>

/* -------------------------------------------------------------------------
 * block(block_addr)
 *
 * Return a reference to the data array for the block keyed by block_addr,
 * creating and zero-initialising it if it does not yet exist.
 *
 * Mirrors the private block() accessor in PR#1549 mem.h (lines 86–98):
 *
 *   std::array<uint8_t, BLOCK_SIZE> &block(uint64_t block_addr) {
 *       auto it = m_blocks.find(block_addr);
 *       if (it == m_blocks.end()) {
 *           std::array<uint8_t, BLOCK_SIZE> new_block;
 *           new_block.fill(m_uninitialized_value_func());
 *           auto res = m_blocks.insert({block_addr, new_block});
 *           return res.first->second;
 *       }
 *       return it->second;
 *   }
 * ------------------------------------------------------------------------- */
std::array<uint8_t, Memory::BLOCK_SIZE> &
Memory::block(uint64_t block_addr)
{
    auto it = m_blocks.find(block_addr);
    if (it == m_blocks.end()) {
        std::array<uint8_t, BLOCK_SIZE> new_block;
        new_block.fill(m_uninitialized_value);
        auto res = m_blocks.insert({block_addr, new_block});
        return res.first->second;
    }
    return it->second;
}

/* -------------------------------------------------------------------------
 * write_bytes – mirrors PR#1549 Memory::write_bytes() (mem.h lines 46–58).
 *
 * PR source (C++ reference):
 *   void write_bytes(uint64_t addr, uint64_t addr_size,
 *                    const uint8_t *data, std::size_t len) {
 *       const uint64_t addr_mask = addr_size >= 64 ? ~0ull
 *                                                  : ~(~0ull << addr_size);
 *       while (len > 0) {
 *           addr = addr & addr_mask;
 *           auto &block_data = block(addr / BLOCK_SIZE);
 *           do {
 *               block_data[addr % BLOCK_SIZE] = *data;
 *               ++addr; ++data; --len;
 *           } while (len > 0 && (addr % BLOCK_SIZE) != 0);
 *       }
 *   }
 * ------------------------------------------------------------------------- */
void Memory::write_bytes(uint64_t addr, uint64_t addr_size,
                         const uint8_t *data, std::size_t len)
{
    const uint64_t addr_mask = addr_size >= 64
                               ? ~UINT64_C(0)
                               : ~(~UINT64_C(0) << addr_size);
    while (len > 0) {
        addr = addr & addr_mask;
        auto &block_data = block(addr / BLOCK_SIZE);
        do {
            block_data[addr % BLOCK_SIZE] = *data;
            ++addr; ++data; --len;
        } while (len > 0 && (addr % BLOCK_SIZE) != 0);
    }
}

/* -------------------------------------------------------------------------
 * read_bytes – mirrors PR#1549 Memory::read_bytes() (mem.h lines 31–43).
 *
 * PR source (C++ reference):
 *   void read_bytes(uint64_t addr, uint64_t addr_size,
 *                   uint8_t *data, std::size_t len) const {
 *       const uint64_t addr_mask = ...;
 *       while (len > 0) {
 *           addr = addr & addr_mask;
 *           const auto it = m_blocks.find(addr / BLOCK_SIZE);
 *           do {
 *               *data = (it != m_blocks.end())
 *                       ? it->second[addr % BLOCK_SIZE]
 *                       : m_uninitialized_value;
 *               ++addr; ++data; --len;
 *           } while (len > 0 && (addr % BLOCK_SIZE) != 0);
 *       }
 *   }
 * ------------------------------------------------------------------------- */
void Memory::read_bytes(uint64_t addr, uint64_t addr_size,
                        uint8_t *data, std::size_t len) const
{
    const uint64_t addr_mask = addr_size >= 64
                               ? ~UINT64_C(0)
                               : ~(~UINT64_C(0) << addr_size);
    while (len > 0) {
        addr = addr & addr_mask;
        const auto it = m_blocks.find(addr / BLOCK_SIZE);
        do {
            *data = (it != m_blocks.end())
                    ? it->second[addr % BLOCK_SIZE]
                    : m_uninitialized_value;
            ++addr; ++data; --len;
        } while (len > 0 && (addr % BLOCK_SIZE) != 0);
    }
}
