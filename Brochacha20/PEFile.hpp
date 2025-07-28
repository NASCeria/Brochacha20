#pragma once
#include <Windows.h>
#include <iostream>
#include <psapi.h>

#include "EffectivePatternScanner.hpp"

#include "PEDumper.hpp"

// When you want to run this on another platform than windows, you need to update this file to not use LoadLibraryExW and FreeLibrary etc
// The windows sdk also might need to get ripped 
class PEFile
{
private:
	HMODULE module_;
	DWORD moduleSize_;

public:
	char* GetBase()
	{
		return (char*)module_;
	}

	DWORD GetSize()
	{
		return moduleSize_;
	}

	uintptr_t GetEnd()
	{
		return (uintptr_t)GetBase() + GetSize();
	}

	std::pair<uintptr_t, uintptr_t> GetSectionRange(const char* Name)
	{
		IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)GetBase();
		IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((uintptr_t)dosHeader + dosHeader->e_lfanew);
		IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeaders);
		for (unsigned int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
		{
			if (strcmp((const char*)section[i].Name, Name) == 0)
			{
				return { (uintptr_t)GetBase() + section[i].VirtualAddress, (uintptr_t)GetBase() + section[i].VirtualAddress + section[i].Misc.VirtualSize };
			}
		}
		throw std::runtime_error("Section not found.");
	}

	std::vector<uintptr_t> ScanSection(const char* Name, std::string Pattern,int endResults = -1)
	{
		auto sectionRange = GetSectionRange(Name);
		return Scanner::ScanPattern(sectionRange.first,sectionRange.second,Pattern, endResults);
	}

	// TODO: add check if its inside image range
	std::vector<uintptr_t> ScanPattern(uintptr_t start,std::string Pattern, bool Reverse = false,int endResults = -1)
	{
		if (Reverse)
		{
			return Scanner::RScanPattern(start, (uintptr_t)GetBase(), Pattern,endResults);
		}
		return Scanner::ScanPattern(start, GetEnd(), Pattern);
	}

	// dont use ^^ (exceptions due to RobloxPlayerBeta.dll having gay ass aligntmetns)
	std::vector<uintptr_t> ScanPattern(std::string Pattern, bool Reverse = false, int endResults = -1)
	{
		return ScanPattern((uintptr_t)GetBase() + 0x10000, Pattern,Reverse);
	}

	void Dump(std::string TargetName)
	{
		int err = PEDumper::Dump(module_, TargetName.c_str());
		if (err)
		{
			throw std::runtime_error(std::string("Failed to dump PE File. ") + strerror(err)); // IGNORE PLS LOl
		}

		return;
	}

	PEFile(const wchar_t* filePath)
	{
		module_ = LoadLibraryExW(filePath, NULL, DONT_RESOLVE_DLL_REFERENCES);
		if (!module_)
		{
			throw std::runtime_error("Failed to load PE File.");
		}

		MODULEINFO mi;
		GetModuleInformation(GetCurrentProcess(), module_, &mi, sizeof(mi));

		moduleSize_ = mi.SizeOfImage;
	}
	PEFile(const char* filePath)
	{
		module_ = LoadLibraryExA(filePath, NULL, DONT_RESOLVE_DLL_REFERENCES);
		if (!module_)
		{
			throw std::runtime_error("Failed to load PE file.");
		}

		MODULEINFO mi;
		GetModuleInformation(GetCurrentProcess(), module_, &mi, sizeof(mi));

		moduleSize_ = mi.SizeOfImage;
	}
	~PEFile()
	{
		if (module_)
		{
			FreeLibrary(module_);
		}
	}
};

// savage: hello
// rainbot: yes
// kkkey: free csgo
// ok
// yoru: *insults msddskid
// packgod: calls italian mafia
// dot: dot
// ronet on top
// cam1494: *sucks cock
// astril: *captures flag
// mario d bario: https://cdn.discordapp.com/attachments/1149327254678143038/1398974471632584784/bario-d-bario.png?ex=68875001&is=6885fe81&hm=358107e3b4aeadd7f2366e5ea44cb0ced22fb9ce5893b45a5cd5af44c78a1c8a&
// mouad: https://tenor.com/view/deez-nuts-party-lol-kool-aid-man-koolaid-gif-19151637
// encryqed: *developing dumper 9