//
//  main.cpp
//  llvm2pic32
//

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

using Elf32_Addr = uint32_t; // Program address
using Elf32_Off = uint32_t;  // File offset
using Elf32_Half = uint16_t;
using Elf32_Word = uint32_t;
using Elf32_Sword = int32_t;

struct Elf32_Ehdr {
    unsigned char e_ident[16]; // ELF Identification bytes
    Elf32_Half e_type;      // Type of file (see ET_* below)
    Elf32_Half e_machine;   // Required architecture for this file (see EM_*)
    Elf32_Word e_version;   // Must be equal to 1
    Elf32_Addr e_entry;     // Address to jump to in order to start program
    Elf32_Off e_phoff;      // Program header table's file offset, in bytes
    Elf32_Off e_shoff;      // Section header table's file offset, in bytes
    Elf32_Word e_flags;     // Processor-specific flags
    Elf32_Half e_ehsize;    // Size of ELF header, in bytes
    Elf32_Half e_phentsize; // Size of an entry in the program header table
    Elf32_Half e_phnum;     // Number of entries in the program header table
    Elf32_Half e_shentsize; // Size of an entry in the section header table
    Elf32_Half e_shnum;     // Number of entries in the section header table
    Elf32_Half e_shstrndx;  // Sect hdr table index of sect name string table
};

struct Elf32_Shdr { // Section header.
    Elf32_Word sh_name;      // Section name (index into string table)
    Elf32_Word sh_type;      // Section type (SHT_*)
    Elf32_Word sh_flags;     // Section flags (SHF_*)
    Elf32_Addr sh_addr;      // Address where section is to be loaded
    Elf32_Off sh_offset;     // File offset of section data, in bytes
    Elf32_Word sh_size;      // Size of section, in bytes
    Elf32_Word sh_link;      // Section type-specific header table index link
    Elf32_Word sh_info;      // Section type-specific extra information
    Elf32_Word sh_addralign; // Section address alignment
    Elf32_Word sh_entsize;   // Size of records contained within the section
};

// File types
enum {
    ET_NONE = 0,        // No file type
    ET_REL = 1,         // Relocatable file
    ET_EXEC = 2,        // Executable file
    ET_DYN = 3,         // Shared object file
    ET_CORE = 4,        // Core file
    ET_LOPROC = 0xff00, // Beginning of processor-specific codes
    ET_HIPROC = 0xffff  // Processor-specific
};

// Section types.
enum : unsigned {
    SHT_NULL = 0,                    // No associated section (inactive entry).
    SHT_PROGBITS = 1,                // Program-defined contents.
    SHT_SYMTAB = 2,                  // Symbol table.
    SHT_STRTAB = 3,                  // String table.
    SHT_RELA = 4,                    // Relocation entries; explicit addends.
    SHT_HASH = 5,                    // Symbol hash table.
    SHT_DYNAMIC = 6,                 // Information for dynamic linking.
    SHT_NOTE = 7,                    // Information about the file.
    SHT_NOBITS = 8,                  // Data occupies no space in the file.
    SHT_REL = 9,                     // Relocation entries; no explicit addends.
    SHT_SHLIB = 10,                  // Reserved.
    SHT_DYNSYM = 11,                 // Symbol table.
    SHT_INIT_ARRAY = 14,             // Pointers to initialization functions.
    SHT_FINI_ARRAY = 15,             // Pointers to termination functions.
    SHT_PREINIT_ARRAY = 16,          // Pointers to pre-init functions.
    SHT_GROUP = 17,                  // Section group.
    SHT_SYMTAB_SHNDX = 18,           // Indices for SHN_XINDEX entries.
    SHT_LOOS = 0x60000000,           // Lowest operating system-specific type.
    SHT_LLVM_ODRTAB = 0x6fff4c00,    // LLVM ODR table.
    SHT_GNU_ATTRIBUTES = 0x6ffffff5, // Object attributes.
    SHT_GNU_HASH = 0x6ffffff6,       // GNU-style hash table.
    SHT_GNU_verdef = 0x6ffffffd,     // GNU version definitions.
    SHT_GNU_verneed = 0x6ffffffe,    // GNU version references.
    SHT_GNU_versym = 0x6fffffff,     // GNU symbol versions table.
    SHT_HIOS = 0x6fffffff,           // Highest operating system-specific type.
    SHT_LOPROC = 0x70000000,         // Lowest processor arch-specific type.
    // Fixme: All this is duplicated in MCSectionELF. Why??
    // Exception Index table
    SHT_ARM_EXIDX = 0x70000001U,
    // BPABI DLL dynamic linking pre-emption map
    SHT_ARM_PREEMPTMAP = 0x70000002U,
    //  Object file compatibility attributes
    SHT_ARM_ATTRIBUTES = 0x70000003U,
    SHT_ARM_DEBUGOVERLAY = 0x70000004U,
    SHT_ARM_OVERLAYSECTION = 0x70000005U,
    SHT_HEX_ORDERED = 0x70000000,   // Link editor is to sort the entries in
    // this section based on their sizes
    SHT_X86_64_UNWIND = 0x70000001, // Unwind information
    
    SHT_MIPS_REGINFO = 0x70000006,  // Register usage information
    SHT_MIPS_OPTIONS = 0x7000000d,  // General options
    SHT_MIPS_DWARF = 0x7000001e,    // DWARF debugging section.
    SHT_MIPS_ABIFLAGS = 0x7000002a, // ABI information.
    SHT_HIPROC = 0x7fffffff, // Highest processor arch-specific type.
    SHT_LOUSER = 0x80000000, // Lowest type reserved for applications.
    SHT_HIUSER = 0xffffffff  // Highest type reserved for applications.
};

void
Hex( // TeX §64 and §67
    uint64_t n,
    uint8_t digitsOrLetter, // Not more than 8 digits!
    void (^touchbase)(char s)
)
{
    auto printDigits = ^(char *buf, char digits, void (^progress)(char
      utf8)) { char c;
        while (digits > 0) { digits--;
            if (buf[digits] < 10) { c = '0' + buf[digits]; }
            else { c = 'A' - 10 + buf[digits]; }
            progress(c);
        }
    };
    
    char buf[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    char k = 0;
    do { buf[k] = n % 16; n = n/16; k++; } while (n != 0);
    printDigits(buf, digitsOrLetter, touchbase);
}

#define MIN(a,b) (((a)<(b))?(a):(b))

// The Microchip PIC32 mapping  
Elf32_Addr virtualToPhysical(Elf32_Addr vAddr) { return vAddr & 0x1FFFFFFF; }

int
main(
     int argc,
     const char *argv[]
)
{
    if (argc != 2) { fprintf(stderr, "Usage: llvm2pic32 <elf32 file>");  return 1; }
    const char *pathIn = argv[1];
    FILE *in = fopen(pathIn, "rb");
    if (in == NULL) { return 2; }
    // char pathOut[2048];
    // strcpy(pathOut, pathIn);
    // char *ext = strstr(pathOut, ".elf");
    // *(ext + 1) = 'h'; *(ext + 2) = 'e'; *(ext + 3) = 'x';
    // FILE *out = fopen(pathOut, "w");
    FILE *out = stdout;
    Elf32_Ehdr elfHeader;
    fread(&elfHeader, sizeof(Elf32_Ehdr), 1, in);
    Elf32_Off sectHeaderOffset = elfHeader.e_shoff;
    Elf32_Half sectHeaderCount = elfHeader.e_shnum;
    Elf32_Half sectHeaderSize = elfHeader.e_shentsize;
    Elf32_Half sectionNameStringTableSectionIndex = elfHeader.e_shstrndx;
    Elf32_Half fileType = elfHeader.e_type;
    if (fileType != ET_EXEC) {} // error
    if (sectHeaderSize != sizeof(Elf32_Shdr)) {} // error
    // Read the section name string table
    fseek(in, sectHeaderOffset + sectHeaderSize*sectionNameStringTableSectionIndex, SEEK_SET);
    Elf32_Shdr stringTableHeader;
    fread(&stringTableHeader, sizeof(Elf32_Shdr), 1, in);
    fseek(in, stringTableHeader.sh_offset, SEEK_SET);
    const char *stringTable = (const char *)malloc(stringTableHeader.sh_size);
    fread((void *)stringTable, 1, stringTableHeader.sh_size, in);
    // Read the sections
    //printf("index name offset bytes linaddr type\n");
    for (int i = 0; i < sectHeaderCount; i++) {
        fseek(in, sectHeaderOffset + i*sectHeaderSize, SEEK_SET);
        // long int x = ftell(file); printf("ftell is %ld ", x);
        Elf32_Shdr sectionHeader;
        fread(&sectionHeader, sizeof(Elf32_Shdr), 1, in);
        const char *name = stringTable + sectionHeader.sh_name;
        if (sectionHeader.sh_size != 0 &&
            (strcmp(name, ".text") == 0 || strcmp(name, ".data") == 0 || strcmp(name, ".bss") == 0)) {
            fprintf(stderr, "%d\t%s\t%x\t%x\t%x\t%x\n", i, name, sectionHeader.sh_offset,
                   sectionHeader.sh_size, sectionHeader.sh_addr, sectionHeader.sh_type);
            fseek(in, sectionHeader.sh_offset, SEEK_SET);
            uint64_t bytesLeft = sectionHeader.sh_size;
            uint8_t *sectionData = (uint8_t *)malloc(bytesLeft);
            fread((void *)sectionData, 1, bytesLeft, in);
            // Extended Linear Address
            // :0200000 4FFFF FC  // Two big endian data bytes contains the upper two bytes of a 32-bit address.
            // Note that the programmer expects a physical address and not a
            // virtual address so we have to map back to a physical address space.
            fprintf(out, ":02000004");
            sectionHeader.sh_addr = virtualToPhysical(sectionHeader.sh_addr);
            uint8_t msb = 0xff&(sectionHeader.sh_addr>>24);
            uint8_t lsb = 0xff&(sectionHeader.sh_addr>>16);
            uint8_t checksum = 6 + msb + lsb;
            Hex(msb, 2, ^(char s) { fprintf(out, "%c", s); } );
            Hex(lsb, 2, ^(char s) { fprintf(out, "%c", s); } );
            Hex(-checksum, 2, ^(char s) { fprintf(out, "%c", s); } );
            fprintf(out, "\x0d\x0a");
        again:
            fprintf(out, ":");
            uint64_t bytesInLine = MIN(bytesLeft, 16);
            checksum = bytesInLine;
            Hex(bytesInLine, 2, ^(char s) { fprintf(out, "%c", s); } );
            uint64_t offset = sectionHeader.sh_size - bytesLeft;
            uint16_t address = 0xFFFF&(sectionHeader.sh_addr + offset);
            Hex(address, 4, ^(char s) { fprintf(out, "%c", s); } );
            checksum += 0xff&address;
            checksum += 0xff&(address>>8);
            Hex(0, 2, ^(char s) { fprintf(out, "%c", s); } ); // data follows
            for (int i = 0; i < bytesInLine; i++) {
                uint8_t data = *(sectionData + (i + sectionHeader.sh_size - bytesLeft));
                Hex(data, 2, ^(char s) { fprintf(out, "%c", s); } );
                checksum += data;
            }
            Hex(-checksum, 2, ^(char s) { fprintf(out, "%c", s); } );
            fprintf(out, "\x0d\x0a");
            bytesLeft -= bytesInLine;
            if (bytesLeft > 0) goto again;
        }
    }
    
    fprintf(out, ":00000001FF\x0d\x0a");
    fclose(out); fclose(in);
    return 0;
}
