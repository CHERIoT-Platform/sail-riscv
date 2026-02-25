#include "mem_dump.h"

#include "rts.h"

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/*
 * Minimal ELF64 structures (self-contained to avoid needing <elf.h>,
 * which is unavailable on macOS).
 */

#define EI_NIDENT 16

typedef struct {
  unsigned char e_ident[EI_NIDENT];
  uint16_t      e_type;
  uint16_t      e_machine;
  uint32_t      e_version;
  uint64_t      e_entry;
  uint64_t      e_phoff;
  uint64_t      e_shoff;
  uint32_t      e_flags;
  uint16_t      e_ehsize;
  uint16_t      e_phentsize;
  uint16_t      e_phnum;
  uint16_t      e_shentsize;
  uint16_t      e_shnum;
  uint16_t      e_shstrndx;
} Elf64_Ehdr;

typedef struct {
  uint32_t p_type;
  uint32_t p_flags;
  uint64_t p_offset;
  uint64_t p_vaddr;
  uint64_t p_paddr;
  uint64_t p_filesz;
  uint64_t p_memsz;
  uint64_t p_align;
} Elf64_Phdr;

/* ELF magic and constants */
#define ELFMAG0       0x7fU
#define ELFMAG1       'E'
#define ELFMAG2       'L'
#define ELFMAG3       'F'
#define ELFCLASS64    2
#define ELFDATA2LSB   1
#define EV_CURRENT    1
#define ELFOSABI_NONE 0
#define ET_CORE       4
#define EM_RISCV      243
#define PT_LOAD       1
#define PF_X          0x1U
#define PF_W          0x2U
#define PF_R          0x4U

void mem_dump_elf(const char *filename, uint64_t base, uint64_t size)
{
  FILE *f = fopen(filename, "wb");
  if (!f) {
    fprintf(stderr, "mem_dump: cannot open '%s': %s\n", filename,
            strerror(errno));
    return;
  }

  const uint64_t data_offset = sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr);

  /* Build ELF header */
  Elf64_Ehdr ehdr;
  memset(&ehdr, 0, sizeof(ehdr));
  ehdr.e_ident[0]  = ELFMAG0;
  ehdr.e_ident[1]  = ELFMAG1;
  ehdr.e_ident[2]  = ELFMAG2;
  ehdr.e_ident[3]  = ELFMAG3;
  ehdr.e_ident[4]  = ELFCLASS64;
  ehdr.e_ident[5]  = ELFDATA2LSB;
  ehdr.e_ident[6]  = EV_CURRENT;
  ehdr.e_ident[7]  = ELFOSABI_NONE;
  ehdr.e_type      = ET_CORE;
  ehdr.e_machine   = EM_RISCV;
  ehdr.e_version   = EV_CURRENT;
  ehdr.e_entry     = 0;
  ehdr.e_phoff     = sizeof(Elf64_Ehdr);
  ehdr.e_shoff     = 0;
  ehdr.e_flags     = 0;
  ehdr.e_ehsize    = sizeof(Elf64_Ehdr);
  ehdr.e_phentsize = sizeof(Elf64_Phdr);
  ehdr.e_phnum     = 1;
  ehdr.e_shentsize = 0;
  ehdr.e_shnum     = 0;
  ehdr.e_shstrndx  = 0;

  if (fwrite(&ehdr, sizeof(ehdr), 1, f) != 1) {
    fprintf(stderr, "mem_dump: failed to write ELF header to '%s'\n",
            filename);
    fclose(f);
    return;
  }

  /* Build program header: one PT_LOAD segment covering [base, base+size) */
  Elf64_Phdr phdr;
  memset(&phdr, 0, sizeof(phdr));
  phdr.p_type   = PT_LOAD;
  phdr.p_flags  = PF_R | PF_W | PF_X;
  phdr.p_offset = data_offset;
  phdr.p_vaddr  = base;
  phdr.p_paddr  = base;
  phdr.p_filesz = size;
  phdr.p_memsz  = size;
  phdr.p_align  = 1;

  if (fwrite(&phdr, sizeof(phdr), 1, f) != 1) {
    fprintf(stderr, "mem_dump: failed to write program header to '%s'\n",
            filename);
    fclose(f);
    return;
  }

  /* Write memory contents, reading byte-by-byte via the Sail runtime */
#define MEM_DUMP_CHUNK 4096
  uint8_t buf[MEM_DUMP_CHUNK];
  uint64_t remaining = size;
  uint64_t addr      = base;

  while (remaining > 0) {
    uint64_t chunk = remaining > MEM_DUMP_CHUNK ? MEM_DUMP_CHUNK : remaining;
    for (uint64_t i = 0; i < chunk; i++) {
      buf[i] = (uint8_t)read_mem(addr + i);
    }
    if (fwrite(buf, 1, (size_t)chunk, f) != (size_t)chunk) {
      fprintf(stderr, "mem_dump: failed to write data at 0x%" PRIx64
                      " to '%s'\n",
              addr, filename);
      fclose(f);
      return;
    }
    addr      += chunk;
    remaining -= chunk;
  }
#undef MEM_DUMP_CHUNK

  fclose(f);
}
