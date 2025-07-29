// fuckass bullshit
// 			return (v2853 << 8) | v2854;
// that above me was a copilot commment
// 				inst = Zydis::Disassmemble(inst.offset + inst.inst.length);
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

namespace PEDumper
{
	// --TODO: add error handling like "Insufficent disk space" or "Can't write to file" etc..--
	// done
	errno_t Dump(HMODULE module, const char* TargetName)
	{
		IMAGE_DOS_HEADER* DOS_HEADER = (IMAGE_DOS_HEADER*)module;

		IMAGE_NT_HEADERS* NT_HEADERS = (IMAGE_NT_HEADERS*)((uintptr_t)module + DOS_HEADER->e_lfanew);


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