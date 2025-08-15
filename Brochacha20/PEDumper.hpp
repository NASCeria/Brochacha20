// fuckass bullshit
// 			return (v2853 << 8) | v2854;
// that above me was a copilot commment
// 				inst = Zydis::Disassemble(inst.offset + inst.inst.length);
// that too
// 				if (inst.inst.mnemonic == ZYDIS_MNEMONIC_MOV && inst.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && inst.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
// tf is it writing
// h


// 				{


// alr so 					Result.Data = inst.operands[1].mem.base;
// 					break;
// MEOW CAN THIS AI STOP

// alr so im a meow and dont want to paste some randomass pe dumper so i thought ill just write one rq

#pragma once

#include <windows.h>
#include <stdio.h>

#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

namespace PEDumper
{
	static void RebaseImage(HMODULE module,uintptr_t NewBase)
	{
		IMAGE_DOS_HEADER* DOS_HEADER = (IMAGE_DOS_HEADER*)module;

		IMAGE_NT_HEADERS* NT_HEADERS = (IMAGE_NT_HEADERS*)((uintptr_t)module + DOS_HEADER->e_lfanew);
		PIMAGE_OPTIONAL_HEADER64 OptionalHeader = &NT_HEADERS->OptionalHeader;

		if (OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
		{
			PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)((uintptr_t)module + OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			PIMAGE_BASE_RELOCATION relocEnd = (PIMAGE_BASE_RELOCATION)((uintptr_t)reloc + OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);

			while (reloc < relocEnd && reloc->SizeOfBlock)
			{
				DWORD NumberOfRelocs = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				WORD* RelocData = (WORD*)((uintptr_t)reloc + sizeof(IMAGE_BASE_RELOCATION));
				for (DWORD i = 0; i < NumberOfRelocs; i++)
				{
					if (RELOC_FLAG64(RelocData[i]))
					{
						DWORD_PTR* AddressToFix = (DWORD_PTR*)((uintptr_t)module + reloc->VirtualAddress + (RelocData[i] & 0xFFF));

						DWORD useless;
						VirtualProtect(AddressToFix, sizeof(DWORD_PTR), PAGE_READWRITE, &useless); // mm ugly
						*AddressToFix += NewBase - OptionalHeader->ImageBase;
						VirtualProtect(AddressToFix, sizeof(DWORD_PTR), PAGE_READWRITE, &useless); // mm ugly
					}
				}
				reloc = (PIMAGE_BASE_RELOCATION)((uintptr_t)reloc + reloc->SizeOfBlock);
			}
		}


		DWORD useless;
		VirtualProtect(module, 0x1000, PAGE_READWRITE, &useless); // mm ugly
		OptionalHeader->ImageBase = NewBase;
		VirtualProtect(module, 0x1000, useless, &useless); // mm ugly
	}

	// --TODO: add error handling like "Insufficent disk space" or "Can't write to file" etc..--
	// done
	static errno_t Dump(HMODULE module, const char* TargetName)
	{
		IMAGE_DOS_HEADER* DOS_HEADER = (IMAGE_DOS_HEADER*)module;

		IMAGE_NT_HEADERS* NT_HEADERS = (IMAGE_NT_HEADERS*)((uintptr_t)module + DOS_HEADER->e_lfanew);

		RebaseImage(module, 0x140000000); // Rebase the image to a new base address (0x140000000)

		char* RebuiltImage = (char*)malloc(NT_HEADERS->OptionalHeader.SizeOfImage);
		ZeroMemory(RebuiltImage, NT_HEADERS->OptionalHeader.SizeOfImage);

		// Map Headers(like PE Header)
		memcpy(RebuiltImage, DOS_HEADER, NT_HEADERS->OptionalHeader.SizeOfHeaders);
		
		// TEMPORARY DISABLE "REBASING" DUE TO RTTI FAILING
		//((IMAGE_NT_HEADERS*)(RebuiltImage + DOS_HEADER->e_lfanew))->OptionalHeader.ImageBase = 0x140000000;


		// Map Sections
		IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(NT_HEADERS);
		for (unsigned int i = 0; i < NT_HEADERS->FileHeader.NumberOfSections; i++)
		{

			// roblox set the section shit to NO_ACCESS so we gotta do it ourself
			DWORD useless;
			VirtualProtect((void*)((uintptr_t)module + section[i].VirtualAddress), section[i].Misc.VirtualSize, PAGE_READWRITE, &useless);
			memcpy(RebuiltImage + section[i].PointerToRawData, (void*)((uintptr_t)module + section[i].VirtualAddress),section[i].SizeOfRawData);
		}

		FILE* file;
		errno_t err = fopen_s(&file, TargetName, "wb");
		if(err != 0)
		{
			return err;
		}
		fwrite(RebuiltImage, 1, NT_HEADERS->OptionalHeader.SizeOfImage, file);
		fclose(file);


		return err;
	}
}