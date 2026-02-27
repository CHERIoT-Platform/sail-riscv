/*
 * mem_dump.c – post-execution ELF memory dump
 *
 * Implements the approach from riscv/sail-riscv PR#1549.
 *
 * Writes the settled post-execution memory state as a loadable ELF so that
 * jump/branch/store self-modifications are captured and re-execution is
 * fully reproducible.
 *
 * The produced ELF contains:
 *   PT_LOAD segments  – one per contiguous non-zero block of RAM (sparse).
 *   .shstrtab         – section-name string table (required by libelf).
 *   .strtab           – symbol-name string table.
 *   .symtab           – one entry for the `tohost` symbol so load_sail()
 *                       can find the HTIF exit address on reload.
 *
 * ELF class is chosen to match xlen: ELFCLASS32 for RV32, ELFCLASS64 for
 * RV64.  This is required because the simulator's check_elf() rejects an
 * ELF whose class does not match the model's address width.
 */

#include "mem_dump.h"
#include "riscv_platform_impl.h" /* rv_htif_tohost */
#include "rts.h"                 /* read_mem() from Sail C runtime */

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* =========================================================================
 * Self-contained ELF definitions (no <elf.h> – absent on macOS).
 * ========================================================================= */

#define EI_NIDENT 16

/* ---- ELF32 types --------------------------------------------------------- */
typedef struct {
  unsigned char e_ident[EI_NIDENT];
  uint16_t e_type; uint16_t e_machine; uint32_t e_version;
  uint32_t e_entry; uint32_t e_phoff; uint32_t e_shoff;
  uint32_t e_flags; uint16_t e_ehsize; uint16_t e_phentsize;
  uint16_t e_phnum; uint16_t e_shentsize; uint16_t e_shnum;
  uint16_t e_shstrndx;
} Elf32_Ehdr;  /* 52 bytes */

typedef struct {
  uint32_t p_type; uint32_t p_offset; uint32_t p_vaddr; uint32_t p_paddr;
  uint32_t p_filesz; uint32_t p_memsz; uint32_t p_flags; uint32_t p_align;
} Elf32_Phdr;  /* 32 bytes – flags AFTER memsz in ELF32 */

typedef struct {
  uint32_t sh_name; uint32_t sh_type; uint32_t sh_flags; uint32_t sh_addr;
  uint32_t sh_offset; uint32_t sh_size; uint32_t sh_link; uint32_t sh_info;
  uint32_t sh_addralign; uint32_t sh_entsize;
} Elf32_Shdr;  /* 40 bytes */

typedef struct {
  uint32_t st_name; uint32_t st_value; uint32_t st_size;
  uint8_t  st_info; uint8_t  st_other; uint16_t st_shndx;
} Elf32_Sym;   /* 16 bytes */

/* ---- ELF64 types --------------------------------------------------------- */
typedef struct {
  unsigned char e_ident[EI_NIDENT];
  uint16_t e_type; uint16_t e_machine; uint32_t e_version;
  uint64_t e_entry; uint64_t e_phoff; uint64_t e_shoff;
  uint32_t e_flags; uint16_t e_ehsize; uint16_t e_phentsize;
  uint16_t e_phnum; uint16_t e_shentsize; uint16_t e_shnum;
  uint16_t e_shstrndx;
} Elf64_Ehdr;  /* 64 bytes */

typedef struct {
  uint32_t p_type; uint32_t p_flags;  /* flags BEFORE offset in ELF64 */
  uint64_t p_offset; uint64_t p_vaddr; uint64_t p_paddr;
  uint64_t p_filesz; uint64_t p_memsz; uint64_t p_align;
} Elf64_Phdr;  /* 56 bytes */

typedef struct {
  uint32_t sh_name; uint32_t sh_type; uint64_t sh_flags; uint64_t sh_addr;
  uint64_t sh_offset; uint64_t sh_size; uint32_t sh_link; uint32_t sh_info;
  uint64_t sh_addralign; uint64_t sh_entsize;
} Elf64_Shdr;  /* 64 bytes */

typedef struct {
  uint32_t st_name; uint8_t st_info; uint8_t st_other; uint16_t st_shndx;
  uint64_t st_value; uint64_t st_size;
} Elf64_Sym;   /* 24 bytes */

/* ---- Shared constants ---------------------------------------------------- */
#define ELFMAG0       0x7fU
#define ELFMAG1       'E'
#define ELFMAG2       'L'
#define ELFMAG3       'F'
#define ELFCLASS32    1
#define ELFCLASS64    2
#define ELFDATA2LSB   1
#define EV_CURRENT    1
#define ELFOSABI_NONE 0
#define ET_EXEC       2
#define EM_RISCV      243
#define PT_LOAD       1
#define PF_X          0x1U
#define PF_W          0x2U
#define PF_R          0x4U
#define SHT_NULL      0
#define SHT_STRTAB    3
#define SHT_SYMTAB    2
#define SHN_UNDEF     0
#define SHN_ABS       0xfff1U
#define STB_GLOBAL    1
#define STT_NOTYPE    0
#define STV_DEFAULT   0

/* =========================================================================
 * Static section data (same for ELF32 and ELF64).
 * =========================================================================
 *
 * Section layout (4 sections, indices 0–3):
 *   [0] SHT_NULL      (mandatory first entry)
 *   [1] .shstrtab     (section-name strings; e_shstrndx = 1)
 *   [2] .strtab       (symbol-name strings)
 *   [3] .symtab       (link=2, info=1 → first global at index 1)
 */
#define NSECTIONS 4

/* Section name string table (".shstrtab").
 * Layout: \0 | .shstrtab\0 | .strtab\0 | .symtab\0
 * Offsets: 0       1           11          19           (total 27 bytes) */
static const char k_shstrtab[] = {
  '\0',
  '.','s','h','s','t','r','t','a','b','\0',  /* index  1 */
  '.','s','t','r','t','a','b','\0',           /* index 11 */
  '.','s','y','m','t','a','b','\0'            /* index 19 */
};
#define K_SHSTRTAB_SZ         ((uint64_t)sizeof(k_shstrtab))  /* 27 */
#define K_SHSTRTAB_IDX_NULL       0
#define K_SHSTRTAB_IDX_SHSTRTAB   1
#define K_SHSTRTAB_IDX_STRTAB    11
#define K_SHSTRTAB_IDX_SYMTAB    19

/* Symbol name string table (".strtab").
 * Layout: \0 | tohost\0
 * Offsets: 0    1          (total 8 bytes) */
static const char k_strtab[] = {
  '\0',
  't','o','h','o','s','t','\0'   /* index 1 */
};
#define K_STRTAB_SZ            ((uint64_t)sizeof(k_strtab))   /* 8 */
#define K_STRTAB_IDX_TOHOST    1

/* Section index constants */
#define SEC_NULL     0
#define SEC_SHSTRTAB 1
#define SEC_STRTAB   2
#define SEC_SYMTAB   3

/* =========================================================================
 * Sparse-block scan parameters (mirrors Memory::BLOCK_SIZE from PR#1549).
 * ========================================================================= */
#define BLOCK_SIZE        16U
#define PAGE_SIZE         0x1000ULL
#define CHUNK_SIZE        4096U
/* Size of the low-memory window scanned for exception vectors/handlers.
 * The RISC-V default mtvec is 0x0, so DII-mode exception handlers land
 * at addresses well below the normal RAM base (0x80000000).  We scan
 * the first 64 KB to capture them. */
#define LOW_MEM_SCAN_SIZE UINT64_C(0x10000)

/* =========================================================================
 * Internal helpers
 * ========================================================================= */

/* align_up: named to avoid collision with sail.h's round_up(sail_int*, real) */
static uint64_t align_up(uint64_t v, uint64_t align)
{
  return (v + align - 1) & ~(align - 1);
}

static bool block_is_zero(uint64_t addr, uint64_t len)
{
  for (uint64_t i = 0; i < len; i++)
    if ((uint8_t)read_mem(addr + i) != 0)
      return false;
  return true;
}

typedef struct { uint64_t vaddr; uint64_t size; } Segment;

#define MAX_SEGMENTS  ((64 * 1024 * 1024) / BLOCK_SIZE)

/* Write `len` zero bytes to `f`. Returns false on error. */
static bool write_zeros(FILE *f, uint64_t len)
{
  static const uint8_t z[PAGE_SIZE];
  while (len > 0) {
    uint64_t n = (len > sizeof(z)) ? sizeof(z) : len;
    if (fwrite(z, 1, (size_t)n, f) != (size_t)n)
      return false;
    len -= n;
  }
  return true;
}

/* =========================================================================
 * mem_dump_elf
 * ========================================================================= */
void mem_dump_elf(const char *filename, uint64_t base, uint64_t size,
                  uint64_t entry_point, int xlen)
{
  /* -----------------------------------------------------------------------
   * Pass 1: sparse block scan → Segment list.
   * --------------------------------------------------------------------- */
  Segment *segs = (Segment *)malloc(MAX_SEGMENTS * sizeof(Segment));
  if (!segs) {
    fprintf(stderr, "mem_dump: out of memory (segments)\n");
    return;
  }
  uint32_t nseg   = 0;
  bool     in_seg = false;

  /* ---- Phase 1: low memory [0, LOW_MEM_SCAN_SIZE) ----------------------
   * Captures exception handlers written at address 0x0 (the RISC-V default
   * mtvec).  Only scanned when main RAM starts above this window so we never
   * emit overlapping PT_LOAD segments. */
  if (base >= LOW_MEM_SCAN_SIZE) {
    for (uint64_t addr = 0; addr < LOW_MEM_SCAN_SIZE; addr += BLOCK_SIZE) {
      if (!block_is_zero(addr, (uint64_t)BLOCK_SIZE)) {
        if (!in_seg) {
          if (nseg >= MAX_SEGMENTS) {
            fprintf(stderr, "mem_dump: too many segments, truncating\n");
            break;
          }
          segs[nseg].vaddr = addr;
          segs[nseg].size  = (uint64_t)BLOCK_SIZE;
          nseg++;
          in_seg = true;
        } else {
          segs[nseg - 1].size += (uint64_t)BLOCK_SIZE;
        }
      } else {
        in_seg = false;
      }
    }
    in_seg = false; /* reset for Phase 2 */
  }

  /* ---- Phase 2: main RAM [base, base+size) ------------------------------ */
  for (uint64_t off = 0; off < size; off += BLOCK_SIZE) {
    uint64_t baddr = base + off;
    uint64_t blen  = ((off + BLOCK_SIZE) <= size) ? BLOCK_SIZE : (size - off);
    if (!block_is_zero(baddr, blen)) {
      if (!in_seg) {
        if (nseg >= MAX_SEGMENTS) {
          fprintf(stderr, "mem_dump: too many segments, truncating\n");
          break;
        }
        segs[nseg].vaddr = baddr;
        segs[nseg].size  = blen;
        nseg++;
        in_seg = true;
      } else {
        segs[nseg - 1].size += blen;
      }
    } else {
      in_seg = false;
    }
  }

  /* -----------------------------------------------------------------------
   * Pass 2: pre-compute the entire file layout so we can fill all headers
   *         before writing a single byte (no fseek needed).
   *
   * File structure:
   *   [0]                  ELF header
   *   [ehdr_size]          PT_LOAD program headers  (nseg × phdr_size)
   *   [page-aligned]       segment data             (nseg regions)
   *   [after last seg]     .shstrtab data           (27 bytes)
   *   [+27]                .strtab data             (8 bytes)
   *   [+8]                 .symtab data             (2 × sym_size)
   *   [aligned to 8]       section header table     (4 × shdr_size)
   * --------------------------------------------------------------------- */
  size_t ehdr_size = (xlen == 32) ? sizeof(Elf32_Ehdr) : sizeof(Elf64_Ehdr);
  size_t phdr_size = (xlen == 32) ? sizeof(Elf32_Phdr) : sizeof(Elf64_Phdr);
  size_t shdr_size = (xlen == 32) ? sizeof(Elf32_Shdr) : sizeof(Elf64_Shdr);
  size_t sym_size  = (xlen == 32) ? sizeof(Elf32_Sym)  : sizeof(Elf64_Sym);

  uint64_t phdr_off = (uint64_t)ehdr_size;
  uint64_t data_start = phdr_off + (uint64_t)nseg * phdr_size;

  /* Page-aligned offset for each PT_LOAD segment. */
  uint64_t *seg_offsets = NULL;
  if (nseg > 0) {
    seg_offsets = (uint64_t *)malloc(nseg * sizeof(uint64_t));
    if (!seg_offsets) {
      fprintf(stderr, "mem_dump: out of memory (offsets)\n");
      free(segs);
      return;
    }
  }
  uint64_t cursor = data_start;
  for (uint32_t i = 0; i < nseg; i++) {
    cursor         = align_up(cursor, PAGE_SIZE);
    seg_offsets[i] = cursor;
    cursor        += segs[i].size;
  }

  /* Immediately after the last segment: section data. */
  uint64_t shstrtab_off = cursor;
  uint64_t strtab_off   = shstrtab_off + K_SHSTRTAB_SZ;
  uint64_t symtab_off   = strtab_off   + K_STRTAB_SZ;
  uint64_t symtab_sz    = (uint64_t)2 * sym_size;   /* null + tohost */
  uint64_t shdr_off     = align_up(symtab_off + symtab_sz, 8);

  /* -----------------------------------------------------------------------
   * Open file and write ELF header.
   * --------------------------------------------------------------------- */
  FILE *f = fopen(filename, "wb");
  if (!f) {
    fprintf(stderr, "mem_dump: cannot open '%s': %s\n", filename,
            strerror(errno));
    free(seg_offsets);
    free(segs);
    return;
  }

  /* Build shared e_ident. */
  unsigned char ident[EI_NIDENT];
  memset(ident, 0, sizeof(ident));
  ident[0] = ELFMAG0; ident[1] = ELFMAG1;
  ident[2] = ELFMAG2; ident[3] = ELFMAG3;
  ident[4] = (xlen == 32) ? ELFCLASS32 : ELFCLASS64;
  ident[5] = ELFDATA2LSB;
  ident[6] = EV_CURRENT;
  ident[7] = ELFOSABI_NONE;

  if (xlen == 32) {
    Elf32_Ehdr h; memset(&h, 0, sizeof(h));
    memcpy(h.e_ident, ident, EI_NIDENT);
    h.e_type      = ET_EXEC;
    h.e_machine   = EM_RISCV;
    h.e_version   = EV_CURRENT;
    h.e_entry     = (uint32_t)entry_point;
    h.e_phoff     = (uint32_t)phdr_off;
    h.e_shoff     = (uint32_t)shdr_off;
    h.e_ehsize    = (uint16_t)sizeof(Elf32_Ehdr);
    h.e_phentsize = (uint16_t)sizeof(Elf32_Phdr);
    h.e_phnum     = (uint16_t)nseg;
    h.e_shentsize = (uint16_t)sizeof(Elf32_Shdr);
    h.e_shnum     = NSECTIONS;
    h.e_shstrndx  = SEC_SHSTRTAB;
    if (fwrite(&h, sizeof(h), 1, f) != 1) { goto io_err; }
  } else {
    Elf64_Ehdr h; memset(&h, 0, sizeof(h));
    memcpy(h.e_ident, ident, EI_NIDENT);
    h.e_type      = ET_EXEC;
    h.e_machine   = EM_RISCV;
    h.e_version   = EV_CURRENT;
    h.e_entry     = entry_point;
    h.e_phoff     = phdr_off;
    h.e_shoff     = shdr_off;
    h.e_ehsize    = (uint16_t)sizeof(Elf64_Ehdr);
    h.e_phentsize = (uint16_t)sizeof(Elf64_Phdr);
    h.e_phnum     = (uint16_t)nseg;
    h.e_shentsize = (uint16_t)sizeof(Elf64_Shdr);
    h.e_shnum     = NSECTIONS;
    h.e_shstrndx  = SEC_SHSTRTAB;
    if (fwrite(&h, sizeof(h), 1, f) != 1) { goto io_err; }
  }

  /* -----------------------------------------------------------------------
   * PT_LOAD program headers.
   * ELF32: type,offset,vaddr,paddr,filesz,memsz,flags,align
   * ELF64: type,FLAGS,offset,vaddr,paddr,filesz,memsz,align  (flags 2nd!)
   * --------------------------------------------------------------------- */
  for (uint32_t i = 0; i < nseg; i++) {
    if (xlen == 32) {
      Elf32_Phdr p; memset(&p, 0, sizeof(p));
      p.p_type   = PT_LOAD;
      p.p_offset = (uint32_t)seg_offsets[i];
      p.p_vaddr  = (uint32_t)segs[i].vaddr;
      p.p_paddr  = (uint32_t)segs[i].vaddr;
      p.p_filesz = (uint32_t)segs[i].size;
      p.p_memsz  = (uint32_t)segs[i].size;
      p.p_flags  = PF_R | PF_W | PF_X;
      p.p_align  = (uint32_t)PAGE_SIZE;
      if (fwrite(&p, sizeof(p), 1, f) != 1) { goto io_err; }
    } else {
      Elf64_Phdr p; memset(&p, 0, sizeof(p));
      p.p_type   = PT_LOAD;
      p.p_flags  = PF_R | PF_W | PF_X;
      p.p_offset = seg_offsets[i];
      p.p_vaddr  = segs[i].vaddr;
      p.p_paddr  = segs[i].vaddr;
      p.p_filesz = segs[i].size;
      p.p_memsz  = segs[i].size;
      p.p_align  = PAGE_SIZE;
      if (fwrite(&p, sizeof(p), 1, f) != 1) { goto io_err; }
    }
  }

  /* -----------------------------------------------------------------------
   * Segment data (with page-aligned padding between segments).
   * --------------------------------------------------------------------- */
  {
    uint64_t pos = data_start;
    uint8_t  buf[CHUNK_SIZE];
    for (uint32_t i = 0; i < nseg; i++) {
      if (!write_zeros(f, seg_offsets[i] - pos)) { goto io_err; }
      pos = seg_offsets[i];
      uint64_t rem  = segs[i].size;
      uint64_t addr = segs[i].vaddr;
      while (rem > 0) {
        uint64_t n = (rem > CHUNK_SIZE) ? CHUNK_SIZE : rem;
        for (uint64_t j = 0; j < n; j++)
          buf[j] = (uint8_t)read_mem(addr + j);
        if (fwrite(buf, 1, (size_t)n, f) != (size_t)n) { goto io_err; }
        addr += n; pos += n; rem -= n;
      }
    }
    /* Advance pos to shstrtab_off (no padding needed – immediately follows). */
    (void)pos;
  }

  /* -----------------------------------------------------------------------
   * Section data: .shstrtab, .strtab, .symtab.
   * --------------------------------------------------------------------- */
  if (fwrite(k_shstrtab, 1, sizeof(k_shstrtab), f) != sizeof(k_shstrtab))
    goto io_err;
  if (fwrite(k_strtab, 1, sizeof(k_strtab), f) != sizeof(k_strtab))
    goto io_err;

  /* Symbol table: [0] null, [1] tohost. */
  if (xlen == 32) {
    Elf32_Sym s0; memset(&s0, 0, sizeof(s0));
    if (fwrite(&s0, sizeof(s0), 1, f) != 1) { goto io_err; }
    Elf32_Sym s1; memset(&s1, 0, sizeof(s1));
    s1.st_name  = K_STRTAB_IDX_TOHOST;
    s1.st_value = (uint32_t)rv_htif_tohost;
    s1.st_info  = (uint8_t)((STB_GLOBAL << 4) | STT_NOTYPE);
    s1.st_shndx = (uint16_t)SHN_ABS;
    if (fwrite(&s1, sizeof(s1), 1, f) != 1) { goto io_err; }
  } else {
    Elf64_Sym s0; memset(&s0, 0, sizeof(s0));
    if (fwrite(&s0, sizeof(s0), 1, f) != 1) { goto io_err; }
    Elf64_Sym s1; memset(&s1, 0, sizeof(s1));
    s1.st_name  = K_STRTAB_IDX_TOHOST;
    s1.st_value = rv_htif_tohost;
    s1.st_info  = (uint8_t)((STB_GLOBAL << 4) | STT_NOTYPE);
    s1.st_shndx = (uint16_t)SHN_ABS;
    if (fwrite(&s1, sizeof(s1), 1, f) != 1) { goto io_err; }
  }

  /* Pad to 8-byte alignment before section header table. */
  {
    uint64_t after_symtab = symtab_off + symtab_sz;
    if (!write_zeros(f, shdr_off - after_symtab)) { goto io_err; }
  }

  /* -----------------------------------------------------------------------
   * Section header table (4 entries).
   *
   *   [0] SHT_NULL
   *   [1] .shstrtab  (SHT_STRTAB)
   *   [2] .strtab    (SHT_STRTAB)
   *   [3] .symtab    (SHT_SYMTAB, link=2, info=1)
   * --------------------------------------------------------------------- */
  if (xlen == 32) {
#define WRITE_SHDR32(nm, tp, off, sz, lk, inf, entsz) do { \
      Elf32_Shdr s; memset(&s, 0, sizeof(s));               \
      s.sh_name      = (nm);                                 \
      s.sh_type      = (tp);                                 \
      s.sh_offset    = (uint32_t)(off);                      \
      s.sh_size      = (uint32_t)(sz);                       \
      s.sh_link      = (lk);                                 \
      s.sh_info      = (inf);                                \
      s.sh_addralign = 1;                                    \
      s.sh_entsize   = (entsz);                              \
      if (fwrite(&s, sizeof(s), 1, f) != 1) goto io_err;    \
    } while (0)

    WRITE_SHDR32(0,                       SHT_NULL,   0,            0,              0,         0, 0);
    WRITE_SHDR32(K_SHSTRTAB_IDX_SHSTRTAB, SHT_STRTAB, shstrtab_off, K_SHSTRTAB_SZ, 0,         0, 0);
    WRITE_SHDR32(K_SHSTRTAB_IDX_STRTAB,   SHT_STRTAB, strtab_off,   K_STRTAB_SZ,   0,         0, 0);
    WRITE_SHDR32(K_SHSTRTAB_IDX_SYMTAB,   SHT_SYMTAB, symtab_off,   symtab_sz,     SEC_STRTAB, 1,
                 (uint32_t)sizeof(Elf32_Sym));
#undef WRITE_SHDR32
  } else {
#define WRITE_SHDR64(nm, tp, off, sz, lk, inf, entsz) do {  \
      Elf64_Shdr s; memset(&s, 0, sizeof(s));                \
      s.sh_name      = (nm);                                  \
      s.sh_type      = (tp);                                  \
      s.sh_offset    = (off);                                 \
      s.sh_size      = (sz);                                  \
      s.sh_link      = (lk);                                  \
      s.sh_info      = (inf);                                 \
      s.sh_addralign = 1;                                     \
      s.sh_entsize   = (entsz);                               \
      if (fwrite(&s, sizeof(s), 1, f) != 1) goto io_err;     \
    } while (0)

    WRITE_SHDR64(0,                       SHT_NULL,   0,            0,              0,         0, 0);
    WRITE_SHDR64(K_SHSTRTAB_IDX_SHSTRTAB, SHT_STRTAB, shstrtab_off, K_SHSTRTAB_SZ, 0,         0, 0);
    WRITE_SHDR64(K_SHSTRTAB_IDX_STRTAB,   SHT_STRTAB, strtab_off,   K_STRTAB_SZ,   0,         0, 0);
    WRITE_SHDR64(K_SHSTRTAB_IDX_SYMTAB,   SHT_SYMTAB, symtab_off,   symtab_sz,     SEC_STRTAB, 1,
                 (uint64_t)sizeof(Elf64_Sym));
#undef WRITE_SHDR64
  }

  fprintf(stderr,
          "mem_dump: wrote ELF%d with %u PT_LOAD segment(s) to '%s' "
          "(entry=0x%" PRIx64 ", tohost=0x%" PRIx64 ")\n",
          xlen, nseg, filename, entry_point, rv_htif_tohost);
  goto cleanup;

io_err:
  fprintf(stderr, "mem_dump: I/O error writing '%s': %s\n", filename,
          strerror(errno));

cleanup:
  fclose(f);
  free(seg_offsets);
  free(segs);
}
