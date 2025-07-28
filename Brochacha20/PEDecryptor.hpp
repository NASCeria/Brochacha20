// Forgive my bad code..

#pragma once
#include "PEFile.hpp"
#include "PageDecryptionCore.hpp"

// Demo func
void DecryptPage(uint32_t PageRVA)
{
	PEFile* Client = new PEFile(L"RobloxPlayerBeta.exe");
	PEFile* Loader = new PEFile(L"RobloxPlayerBeta.dll");

	uc_engine* uc;
	PageDecryptorCore::DumpedRegisters Registers;
	uintptr_t DecryptionKeyArrayAddy;

	PageDecryptorCore::InitializeDecryptionEmulation(Loader, &uc, &DecryptionKeyArrayAddy, Registers);

	auto textSection = Client->GetSectionRange(".text");
	uint32_t textSectionStartRVA = textSection.first - (uintptr_t)Client->GetBase();
	uint32_t textSectionEndRVA = textSection.second - (uintptr_t)Client->GetBase();

	__uint128 DecryptionKeys[2];
	PageDecryptorCore::Calculations::GetDecryptionKeys(PageDecryptorCore::Calculations::GetPageId(PageRVA), DecryptionKeyArrayAddy, DecryptionKeys);

	PageDecryptorCore::PageDecryptionState PageState;
	PageState.Data = (char*)Client->GetBase() + PageRVA;
	PageState.DecryptionKey1 = DecryptionKeys[0];
	PageState.DecryptionKey2 = DecryptionKeys[1];
	PageState.PageRVA = PageRVA;
	PageState.PageID = PageDecryptorCore::Calculations::GetPageId(PageRVA);

	try
	{
		PageDecryptorCore::StartDecryptionEmulation(uc, &Registers, &PageState);
	}
	catch (const std::exception& ex)
	{
		std::cout << "Critical Exception in Decryption Emulation: " << ex.what() << std::endl;
	}

	std::cout << "Decryption Finished!" << std::endl;
	std::cout << "Base: " << std::hex << (uintptr_t)Client->GetBase() << std::endl;
	std::cout << "Data: " << std::hex << (uintptr_t)PageState.Data << std::endl;
	getchar();
}

// Demo func
void DecryptAllPages()
{
	PEFile* Client = new PEFile(L"C:\\Users\\Mark\\AppData\\Local\\Fishstrap\\Versions\\version-225e87fdb7254f64\\RobloxPlayerBeta.exe"); 
	PEFile* Loader = new PEFile(L"C:\\Users\\Mark\\AppData\\Local\\Fishstrap\\Versions\\version-225e87fdb7254f64\\RobloxPlayerBeta.dll");

	uc_engine* uc;
	PageDecryptorCore::DumpedRegisters Registers;
	uintptr_t DecryptionKeyArrayAddy;

	PageDecryptorCore::InitializeDecryptionEmulation(Loader, &uc, &DecryptionKeyArrayAddy, Registers);

	auto textSection = Client->GetSectionRange(".text");
	uint32_t textSectionStartRVA = textSection.first - (uintptr_t)Client->GetBase();
	uint32_t textSectionEndRVA = textSection.second - (uintptr_t)Client->GetBase();

	for (uint64_t pageRVA = textSectionStartRVA; pageRVA < textSectionEndRVA; pageRVA += 0x1000)
	{

		std::cout << "CurrentPageRVA: " << std::hex << pageRVA << std::endl;

		__uint128 DecryptionKeys[2];
		PageDecryptorCore::Calculations::GetDecryptionKeys(PageDecryptorCore::Calculations::GetPageId(pageRVA), DecryptionKeyArrayAddy, DecryptionKeys);

		PageDecryptorCore::PageDecryptionState PageState;
		PageState.Data = (char*)Client->GetBase() + pageRVA;
		PageState.DecryptionKey1 = DecryptionKeys[0];
		PageState.DecryptionKey2 = DecryptionKeys[1];
		PageState.PageRVA = pageRVA;
		PageState.PageID = PageDecryptorCore::Calculations::GetPageId(pageRVA);

		try
		{
			PageDecryptorCore::StartDecryptionEmulation(uc, &Registers, &PageState);
		}
		catch (const std::exception& ex)
		{
			std::cout << "Critical Exception in Decryption Emulation: " << ex.what() << std::endl;
			break;
		}
	}

	std::cout << "Decryption Finished!" << std::endl;
	std::cout << "Base: " << std::hex << (uintptr_t)Client->GetBase() << std::endl;

	//Client->Dump();
}

// Returns decrypted client
PEFile* DecryptRBXClient(const std::string RobloxPath)
{
	PEFile* Client = new PEFile((RobloxPath + "\\RobloxPlayerBeta.exe").c_str());
	PEFile* Loader = new PEFile((RobloxPath + "\\RobloxPlayerBeta.dll").c_str());

	uc_engine* uc;
	PageDecryptorCore::DumpedRegisters Registers;
	uintptr_t DecryptionKeyArrayAddy;

	PageDecryptorCore::InitializeDecryptionEmulation(Loader, &uc, &DecryptionKeyArrayAddy, Registers);

	auto textSection = Client->GetSectionRange(".text");
	uint32_t textSectionStartRVA = textSection.first - (uintptr_t)Client->GetBase();
	uint32_t textSectionEndRVA = textSection.second - (uintptr_t)Client->GetBase();

	for (uint64_t pageRVA = textSectionStartRVA; pageRVA < textSectionEndRVA; pageRVA += 0x1000)
	{
		// TODO: add percentage prints
		//Logger::Debug("Current Page: %p", pageRVA);

		__uint128 DecryptionKeys[2];
		PageDecryptorCore::Calculations::GetDecryptionKeys(PageDecryptorCore::Calculations::GetPageId(pageRVA), DecryptionKeyArrayAddy, DecryptionKeys);

		PageDecryptorCore::PageDecryptionState PageState;
		PageState.Data = (char*)Client->GetBase() + pageRVA;
		PageState.DecryptionKey1 = DecryptionKeys[0];
		PageState.DecryptionKey2 = DecryptionKeys[1];
		PageState.PageRVA = pageRVA;
		PageState.PageID = PageDecryptorCore::Calculations::GetPageId(pageRVA);

		try
		{
			PageDecryptorCore::StartDecryptionEmulation(uc, &Registers, &PageState);
		}
		catch (const std::exception& ex)
		{
			Logger::Error("Critical Exception in Decryption Emulation: %s",ex.what());

			return nullptr;
		}
	}

	delete Loader;

	return Client;
}