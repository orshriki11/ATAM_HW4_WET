#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#include "elf64.h"

#define	ET_NONE	0	//No file type 
#define	ET_REL	1	//Relocatable file 
#define	ET_EXEC	2	//Executable file 
#define	ET_DYN	3	//Shared object file 
#define	ET_CORE	4	//Core file

#define SHT_SYMTAB 2 //symtab Sh Type
#define SHT_DYNSYM 0x0b //dymsym Sh Type
#define STB_GLOBAL 1 //Global Bind


/* symbol_name		- The symbol (maybe function) we need to search for.
 * exe_file_name	- The file where we search the symbol in.
 * error_val		- If  1: A global symbol was found, and defined in the given executable.
 * 			- If -1: Symbol not found.
 *			- If -2: Only a local symbol was found.
 * 			- If -3: File is not an executable.
 * 			- If -4: The symbol was found, it is global, but it is not defined in the executable.
 * return value		- The address which the symbol_name will be loaded to, if the symbol was found and is global.
 */
unsigned long find_symbol(char* symbol_name, char* exe_file_name, int* error_val) {
	Elf64_Ehdr elf_header;
    bool symbol_is_local = false;
    bool symbol_is_global = false;
    bool symbol_is_UNDEF = false;
    FILE* file = fopen(exe_file_name, "rb");
    if(file)
    {
        fread(&elf_header,sizeof(elf_header), 1 , file);
        if(elf_header.e_ident[0] != 0x7f || elf_header.e_ident[1] != 'E'
            || elf_header.e_ident[2] != 'L' || elf_header.e_ident[3] != 'F')
        {
            *error_val = -3;
            return 0;
        }

        if(elf_header.e_type != ET_EXEC)
        {
            *error_val = -3;
            return 0;
        }

        Elf64_Shdr section_header[elf_header.e_shnum];
        unsigned int amount_of_sections = elf_header.e_shnum;
        int symtab_index = -1;
        int dymsymtab_index = -1;

        for(int i = 0; i < amount_of_sections;i++)
        {
            fseek(file, elf_header.e_shoff + i * elf_header.e_shentsize, SEEK_SET);
            fread(&section_header[i], elf_header.e_shentsize, 1,
                   file);

            if(section_header[i].sh_type == SHT_SYMTAB)
            {
                symtab_index = i;
            }

            if(section_header[i].sh_type == SHT_DYNSYM)
            {
                dymsymtab_index = i;
            }
        }


        if(symtab_index < 0)
        {
            *error_val = -3;
            return 0;
        }
        Elf64_Shdr symtab_header = section_header[symtab_index];
        Elf64_Shdr strtab_header = section_header[symtab_header.sh_link];
        unsigned long long amount_of_symbols = symtab_header.sh_size / sizeof(Elf64_Sym);
        Elf64_Sym symbols[amount_of_symbols];
        bool valid_Symbols[amount_of_symbols];
        int amount_of_valid_symbols = 0;
        int wanted_symbol_index = -1;


        char *strtable = malloc(strtab_header.sh_size);
        fseek(file, strtab_header.sh_offset, SEEK_SET);
        fread(strtable, strtab_header.sh_size,1, file);


        fseek(file, symtab_header.sh_offset, SEEK_SET);
        fread(symbols, symtab_header.sh_size,
              1,file);

        for(int i = 0; i < amount_of_symbols; i++)
        {
            if(strcmp(strtable + symbols[i].st_name,symbol_name) == 0)
            {
                wanted_symbol_index = i;
                valid_Symbols[i] = true;
                amount_of_valid_symbols++;
            }
            else
            {
                valid_Symbols[i] = false;
            }

        }

        if(amount_of_valid_symbols < 1)
        {
            *error_val = -1;
            return 0;
        }
        if(amount_of_symbols == 1)
        {
            Elf64_Sym f_symbol = symbols[wanted_symbol_index];
            unsigned bind = f_symbol.st_info;
            if(ELF64_ST_BIND(bind) == STB_GLOBAL)
            {
                symbol_is_global = true;
            }
            if(ELF64_ST_BIND(bind) != STB_GLOBAL)
            {
                symbol_is_local = true;
            }
            if(f_symbol.st_shndx == SHN_UNDEF && symbol_is_global)
            {
                symbol_is_UNDEF = true;
                //*error_val = -4;
                //return 0;
            }
            if(symbol_is_local && !symbol_is_global)
            {
                *error_val = -2;
                return 0;
            }
            if(f_symbol.st_shndx != SHN_UNDEF && symbol_is_global)
            {
                *error_val = 1;
                return f_symbol.st_value;
            }

        }
        else
        {
            for(int i=0;i<amount_of_symbols;i++)
            {
                if(valid_Symbols[i])
                {
                    if(ELF64_ST_BIND(symbols[i].st_info) == STB_GLOBAL )
                    {
                        symbol_is_global = true;
                        if(symbols[i].st_shndx != SHN_UNDEF)
                        {
                            *error_val = 1;
                            return symbols[i].st_value;
                        }
                        else
                        {
                            symbol_is_UNDEF = true;
                            *error_val = -4;
                            //return 0;
                        }

                    }
                    else if(ELF64_ST_BIND(symbols[i].st_info) != 1)
                    {
                        symbol_is_local = true;
                    }
                }
            }
            if(symbol_is_local && !symbol_is_global)
            {
                *error_val = -2;
                return 0;
            }
        }

        if(symbol_is_UNDEF)
        {
            int section_str_index = elf_header.e_shstrndx;
            int wanted_relaTable_index = -1;
            Elf64_Shdr shstr_header = section_header[section_str_index];

            char *strshtable = malloc(shstr_header.sh_size);
            fseek(file, shstr_header.sh_offset, SEEK_SET);
            fread(strshtable, shstr_header.sh_size,1, file);


            for(int i = 0; i < amount_of_sections;i++)
            {
                //fseek(file, elf_header.e_shoff + i * elf_header.e_shentsize, SEEK_SET);
                //fread(&section_header[i], elf_header.e_shentsize, 1,
                      file);

                if(strcmp(strshtable + section_header[i].st_name,".rela.plt") == 0)
                {
                    wanted_relaTable_index = i;
                }
            }

            Elf64_Shdr dymsym_header = section_header[dymsymtab_index];
            Elf64_Shdr reloctions_table = section_header[wanted_relaTable_index];

            unsigned long long amount_of_rela = reloctions_table.sh_size / sizeof(Elf64_Rela);
            Elf64_Rela relocations[amount_of_rela];

            unsigned long long amount_of_dymsym = dymsym_header.sh_size / sizeof(Elf64_Sym);
            Elf64_Sym dymsymbols[amount_of_dymsym];


            fseek(file, dymsym_header.sh_offset, SEEK_SET);
            fread(dymsymbols, dymsym_header.sh_size,
                  1,file);

            fseek(file, reloctions_table.sh_offset, SEEK_SET);
            fread(relocations, reloctions_table.sh_size,
                  1,file);

            int wanted_dymsymbol_index = -1;

            for(int i = 0; i < amount_of_dymsym;i++)
            {
                //fseek(file, elf_header.e_shoff + i * elf_header.e_shentsize, SEEK_SET);
                //fread(&section_header[i], elf_header.e_shentsize, 1,
                file);

                if(strcmp(strtable + dymsym_header[i].st_name,symbol_name) == 0)
                {
                    wanted_dymsymbol_index = i;
                }
            }

            int relocation_found_index = -1;


            for(int i = 0; i < amount_of_rela; i++) {
                if(ELF64_R_SYM(relocations[i].r_info) == wanted_dymsymbol_index)
                {
                    relocation_found_index = i;
                }

            }


            fread(&section_header[i], elf_header.e_shentsize, 1,
                  file);


        }
    }


	return 0;
}

int main(int argc, char *const argv[]) {
	int err = 0;
	unsigned long addr = find_symbol(argv[1], argv[2], &err);

	if (err > 0)
		printf("%s will be loaded to 0x%lx\n", argv[1], addr);
	else if (err == -2)
		printf("%s is not a global symbol! :(\n", argv[1]);
	else if (err == -1)
		printf("%s not found!\n", argv[1]);
	else if (err == -3)
		printf("%s not an executable! :(\n", argv[2]);
	else if (err == -4)
		printf("%s is a global symbol, but will come from a shared library\n", argv[1]);
	return 0;
}