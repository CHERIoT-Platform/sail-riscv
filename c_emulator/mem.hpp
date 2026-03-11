/*
 * mem.hpp – first-party sparse memory model for the RVFI DII simulator.
 *
 * Direct C++ port of c_emulator/mem.h from riscv/sail-riscv PR#1549
 * ("Add first party memory model with support for memory dumps").
 *
 * The memory model is a sparse map of fixed-size blocks:
 *
 *   std::map<uint64_t, std::array<uint8_t, BLOCK_SIZE>> m_blocks
 *
 * where the map key is (addr / BLOCK_SIZE).  Only blocks that have been
 * written are stored, keeping the footprint small for typical workloads.
 *
 * Public API mirrors PR#1549 Memory:
 *   write_bytes   – store bytes into the model
 *   read_bytes    – load bytes from the model (unwritten → 0)
 *   for_each_byte – iterate every byte in every allocated block in address
 *                   order (template, defined inline below)
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>

class Memory {
public:
    /* Block granularity – mirrors Memory::BLOCK_SIZE in PR#1549. */
    static constexpr std::size_t BLOCK_SIZE = 16;

    /* ------------------------------------------------------------------
     * write_bytes(addr, addr_size, data, len)
     *
     * Write `len` bytes from `data` into the model starting at `addr`.
     * `addr_size` is the physical address width in bits (32 or 64);
     * addresses are masked to this width before use.
     *
     * Mirrors PR#1549 Memory::write_bytes().
     * ------------------------------------------------------------------ */
    void write_bytes(uint64_t addr, uint64_t addr_size,
                     const uint8_t *data, std::size_t len);

    /* ------------------------------------------------------------------
     * read_bytes(addr, addr_size, data, len) const
     *
     * Read `len` bytes from the model into `data`.
     * Unwritten addresses read back as m_uninitialized_value (0).
     *
     * Mirrors PR#1549 Memory::read_bytes().
     * ------------------------------------------------------------------ */
    void read_bytes(uint64_t addr, uint64_t addr_size,
                    uint8_t *data, std::size_t len) const;

    /* ------------------------------------------------------------------
     * for_each_byte(func, skip_if_equal_uninitialized)
     *
     * Call func(addr, value) for every byte in every allocated block,
     * in ascending address order.
     *
     * skip_if_equal_uninitialized:
     *   true  – skip bytes whose value equals m_uninitialized_value (0).
     *   false – visit all bytes in every allocated block.
     *
     * Direct C++ port of PR#1549 mem.h for_each_byte template:
     *
     *   template <typename F>
     *   void for_each_byte(F func, bool skip_if_equal_uninitialized) const {
     *       for (const auto &[block_addr, block_data] : m_blocks) {
     *           uint64_t addr = block_addr * BLOCK_SIZE;
     *           for (std::size_t i = 0; i < BLOCK_SIZE; i++) {
     *               if (!skip_if_equal_uninitialized || ...)
     *                   func(addr, block_data[i]);
     *               ++addr;
     *           }
     *       }
     *   }
     * ------------------------------------------------------------------ */
    template <typename F>
    void for_each_byte(F func,
                       bool skip_if_equal_uninitialized = true) const
    {
        const uint8_t uninit = m_uninitialized_value;
        for (const auto &[block_addr, block_data] : m_blocks) {
            uint64_t addr = block_addr * BLOCK_SIZE;
            for (std::size_t i = 0; i < BLOCK_SIZE; i++) {
                if (!skip_if_equal_uninitialized ||
                    block_data[i] != uninit)
                    func(addr, block_data[i]);
                ++addr;
            }
        }
    }

private:
    /* Return (creating if absent) the data array for block_addr. */
    std::array<uint8_t, BLOCK_SIZE> &block(uint64_t block_addr);

    std::map<uint64_t, std::array<uint8_t, BLOCK_SIZE>> m_blocks;

    /* Value used for blocks that have never been written.
     * Matches PR#1549 default (m_uninitialized_value_func returns 0). */
    uint8_t m_uninitialized_value = 0;
};
