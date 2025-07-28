// Hello dear Explorer!! This is my badly organised code which reflects my poor Cpp/C skills!
// Overall the logic is what matters! checkout my great reversal!

// --TODO: maybe cleanup this bullshit and create more structs instead of passing 5 parameters to every second function--
// finished

#include <windows.h>
#include <iostream>

#include "PeFile.hpp"
#include "Emulation.hpp"

constexpr uint64_t EMULATION_DECRYPTION_BASE_DATA_ADDRESS = 0x20000000;

namespace PageDecryptorCore
{
	// When first 2 bytes match RBP then the last 2 bytes are the displacement
	// Register: DumpedRegister & 0xFFFF
	// Displacement: DumpedRegister >> 16
	struct DumpedRegisters
	{
		DWORD PageRVA;
		DWORD PageRVA2; // Extension for PageRVA when PageRVA is on the stack
		DWORD DecryptionKey1;
		DWORD DecryptionKey2;
		DWORD Data;
		DWORD OffsetKey1;
		DWORD OffsetKey2;
	};

	// Contains all information required for its decryption
	struct PageDecryptionState
	{
		uint64_t PageRVA;
		uint64_t PageID;
		__uint128 DecryptionKey1;
		__uint128 DecryptionKey2;
		char* Data;

		// Actually those dont change but i do not want to create another struct just for 2 ptrs (actually would be smart it could contain the decryptionkeyarray too)
		//uintptr_t DecryptionStart;
		//uintptr_t DecryptionEnd;
		// nvm..
	};

	namespace Calculations
	{
		// Maybe make it a macro? (A typical PageRVA looks like this: 0x0111B000)
		uint32_t GetPageId(uintptr_t PageRVA)
		{
			return PageRVA >> 12;
		}

		// Appears to be useless..? The pageblock always has zeroes at those locations even when fully allocated
		uint64_t CalculateOffsetKey(uint64_t PageRVA, uintptr_t KeyBlock)
		{
			/*
			uint8_t PageDecryKey1 = *(uint8_t*)(KeyBlock + 158);

			uint8_t v2853 = *(BYTE*)(KeyBlock + 197) ^ __ROL1__(*(BYTE*)(KeyBlock + 4 * PageDecryKey1 + 174), 2);
			uint8_t v2854 = *(BYTE*)(KeyBlock + 198) ^ __ROL1__(*(BYTE*)(KeyBlock + 4 * PageDecryKey1 + 175), 2);
			uint8_t v2855 = *(BYTE*)(KeyBlock + 199) ^ __ROL1__(*(BYTE*)(KeyBlock + 4 * PageDecryKey1 + 176), 2);
			uint8_t v2856 = *(BYTE*)(KeyBlock + 200) ^ __ROL1__(*(BYTE*)(KeyBlock + 4 * PageDecryKey1 + 177), 2);

			uint64_t OffsetKey1 = (v2856 << 24) | (v2855 << 16) | (v2854 << 8) | v2853;
			uint64_t OffsetKey2 = PageRVA << 32;
			
			return OffsetKey1 + OffsetKey2;
			*/

			return PageRVA << 32;
		}


		// A typical PageId looks like this: 111B
		void GetDecryptionKeys(uint32_t PageId, uintptr_t DecryptionKeyArray, __uint128 Keys[2])
		{
			uint64_t DecryptionKeyOffset = (PageId % 0x2004) * 32;
			__uint128 DecryptionKey1 = *(__uint128*)(DecryptionKeyArray + DecryptionKeyOffset);
			__uint128 DecryptionKey2 = *(__uint128*)(DecryptionKeyArray + DecryptionKeyOffset + 16);

			Keys[0] = DecryptionKey1;
			Keys[1] = DecryptionKey2;
		}
	}

	namespace Dumper
	{
		// yoru likes to lick savage's puppy furry feet btw
		void DumpRegisters(uintptr_t StartRange, uintptr_t DecryptionKeyOffsetInst, DumpedRegisters& Result)
		{
			Zydis::ZydisDecodedFullInstruction inst = Zydis::Disassmemble(StartRange);

			// We expect the PageRetrieve to be mov PageRVA, [RBP + Displacement] OR A Random ass Instruction!
			auto pageRetrieve = Zydis::Disassmemble(StartRange - 7); // we need to check if hyperion has a register dedicated to the page or it is on the stack

			//std::cout << std::hex << pageRetrieve.offset << " " << Zydis::FormatInstruction(pageRetrieve) << std::endl;

			// Probably stack
			if (pageRetrieve.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY && pageRetrieve.operands[1].mem.base == ZYDIS_REGISTER_RBP)
			{
				// Stack!
				Result.PageRVA = (pageRetrieve.operands[1].mem.disp.value << 16) | ZYDIS_REGISTER_RBP;
				Result.PageRVA2 = inst.operands[1].mem.base;
			}
			else
			{
				Result.PageRVA = inst.operands[1].mem.base;
			}

			// DecryptionKey1 and DecryptionKey2

			auto DecryptionKeyOffsetInstDis = Zydis::Disassmemble(DecryptionKeyOffsetInst);
			auto StoreDecryptionKey1Inst = Zydis::Disassmemble(DecryptionKeyOffsetInstDis.offset + DecryptionKeyOffsetInstDis.inst.length);
			auto StoreDecryptionKey2Inst = Zydis::Disassmemble(StoreDecryptionKey1Inst.offset + StoreDecryptionKey1Inst.inst.length);

			Result.DecryptionKey1 = StoreDecryptionKey1Inst.operands[0].reg.value;
			Result.DecryptionKey2 = StoreDecryptionKey2Inst.operands[0].reg.value;

			inst = Zydis::Disassmemble(StartRange);
			while (true)
			{
				if (inst.inst.mnemonic == ZYDIS_MNEMONIC_LEA && inst.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY && inst.operands[1].mem.disp.value == 0x10)
				{
					Result.Data = inst.operands[1].mem.base;
					break;
				}
				inst = Zydis::Disassmemble(inst.offset + inst.inst.length);
			}

			// TOOD: maybe scan until startrange and when its not found then it MUST be after   shr ??, 0C; ?? ??, 7FFFh; shl ??, 2Ch
			auto pageOffsetCalcRes = Scanner::ScanPattern(StartRange - 0x200, StartRange + 0x100, "C1 ?? 0C ?? ?? FF 7F 00 00 48 C1 ?? 2C",1);
			if (pageOffsetCalcRes.empty())
			{
				pageOffsetCalcRes = Scanner::ScanPattern(StartRange - 0x200, StartRange + 0x100, "C1 ?? 0C ?? FF 7F 00 00 48 C1 ?? 2C", 1);
			}

			uintptr_t pageOffsetCalc = pageOffsetCalcRes.back();
			Logger::Debug("PageOffsetCalc %p", pageOffsetCalc);
			// Does the page offset get computed after or before our emulation start?
			if (pageOffsetCalc < StartRange)
			{
				// Before
				inst = Zydis::Disassmemble(StartRange);
				while (true)
				{
					if (inst.inst.mnemonic == ZYDIS_MNEMONIC_MOV && inst.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && inst.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
					{
						uint8_t possibleOffsetKey1 = inst.operands[1].reg.value;
						inst = Zydis::Disassmemble(inst.offset + inst.inst.length);
						if (inst.inst.mnemonic == ZYDIS_MNEMONIC_NOT && inst.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
						{
							Result.OffsetKey1 = possibleOffsetKey1;
							break;
						}
					}
					inst = Zydis::Disassmemble(inst.offset + inst.inst.length);
				}
			}
			else
			{
				// After
				Result.OffsetKey1 = ZYDIS_REGISTER_NONE;
			}

			
			Logger::Debug("[Dumped Registers Start]");
			Logger::Debug("DecryptionKey1: %s", ZydisRegisterGetString((ZydisRegister)Result.DecryptionKey1));
			Logger::Debug("DecryptionKey2: %s", ZydisRegisterGetString((ZydisRegister)Result.DecryptionKey2));
			Logger::Debug("OffsetKey1: %s", ZydisRegisterGetString((ZydisRegister)Result.OffsetKey1));
			Logger::Debug("PageRVA: %s", ZydisRegisterGetString((ZydisRegister)(Result.PageRVA & 0xFFFF)));
			Logger::Debug("Data: %s", ZydisRegisterGetString((ZydisRegister)(Result.Data)));
			Logger::Debug("[Dumped Registers End]");

		}

		// first: instruction offset second: decryptionKeys in memory
		// Start can be any address that isnt behind where it acceses the decryption keys (start range as example would work)
		std::pair<uintptr_t, uintptr_t> FetchDecryptionKeyOffset(PEFile* Pe, uintptr_t Start)
		{
			uintptr_t imulInst = Pe->ScanPattern(Start, "01 F8 3F 00", true, 1).back() - 3; // search for the 3FF801h operand which is used to calculate the decryption key offset

			Zydis::ZydisDecodedFullInstruction inst = Zydis::Disassmemble(imulInst);
			while (true)
			{
				inst = Zydis::Disassmemble(inst.offset + inst.inst.length);
				if (inst.inst.mnemonic == ZYDIS_MNEMONIC_LEA && inst.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY && inst.operands[1].mem.base == ZYDIS_REGISTER_RIP)
				{
					return std::make_pair(inst.offset, inst.offset + inst.inst.length + inst.operands[1].mem.disp.value);
				}
			}

			throw std::runtime_error("Failed to find decryption key offset");
		}

		std::pair<uintptr_t, uintptr_t> FetchEmulationRange(PEFile* Pe)
		{
			uintptr_t s = Pe->ScanSection(".byfron", "66 0F 6F ?? 66 0F 73 ?? 20 66 0F 6F ?? 66 0F 73 ?? 20 66 44 0F 6F ?? 66 41 0F 73 D0 20 66 44 0F 6F ?? 66 41 0F 73 D1 20")[0];
			uintptr_t pageSubInst = Pe->ScanPattern(s, "00 F0 FF FF", true, 1).back() - 3; // search for the -1000h


			Zydis::ZydisDecodedFullInstruction inst = Zydis::Disassmemble(pageSubInst);
			while (true)
			{
				inst = Zydis::Disassmemble(inst.offset + inst.inst.length);
				if (inst.inst.mnemonic == ZYDIS_MNEMONIC_JMP)
				{
					return std::make_pair(pageSubInst, inst.offset + inst.operands[0].imm.value.u + inst.inst.length);
				}
			}

			throw std::runtime_error("Failed to find range");
		}

	}

	uc_context* BuildContext(uc_engine* uc,DumpedRegisters* Registers, PageDecryptionState* PageState)
	{
		uc_context* context;
		uc_context_alloc(uc, &context);
		uc_context_save(uc,context);

		Emulation::ClearEssentialRegisters(context);

		uc_context_reg_write(context, Emulation::ZydisReg2Uc((ZydisRegister_)Registers->DecryptionKey1), &PageState->DecryptionKey1);
		uc_context_reg_write(context, Emulation::ZydisReg2Uc((ZydisRegister_)Registers->DecryptionKey2), &PageState->DecryptionKey2);
		uc_context_reg_write(context, Emulation::ZydisReg2Uc((ZydisRegister_)Registers->Data), &EMULATION_DECRYPTION_BASE_DATA_ADDRESS);
		if ((Registers->PageRVA & 0x0000FFFF) == ZYDIS_REGISTER_RBP)
		{
			uint16_t disp = Registers->PageRVA >> 16; // Extract the displacement

			uintptr_t rbp;
			uc_context_reg_read(context, Emulation::ZydisReg2Uc(ZYDIS_REGISTER_RBP), &rbp);
			uc_mem_write(uc, rbp + disp, &PageState->PageRVA, 8);
			
			uc_context_reg_write(context, Emulation::ZydisReg2Uc((ZydisRegister_)Registers->PageRVA2), &PageState->PageRVA);
		}
		else
		{
			uc_context_reg_write(context, Emulation::ZydisReg2Uc((ZydisRegister_)Registers->PageRVA), &PageState->PageRVA);
		}

		if (Registers->OffsetKey1 != ZYDIS_REGISTER_NONE)
		{
			uintptr_t offsetKey1 = PageState->PageRVA << 32;
			uc_context_reg_write(context, Emulation::ZydisReg2Uc((ZydisRegister_)Registers->OffsetKey1), &offsetKey1);
		}


		auto xmm7 = _mm_set_epi64x(0xffffffffffffffff, 0xffffffffffffffff);
		uc_reg_write(uc, UC_X86_REG_XMM7, &xmm7);

		return context;
	}

	uc_engine* SetupEmulation()
	{
		uc_engine* uc = Emulation::SetupEmulation();
		return uc;
	}

	void SetupEmulationContext(uc_engine* uc,DumpedRegisters* Registers, PageDecryptionState* PageState)
	{
		uc_context* context = BuildContext(uc, Registers, PageState);
		uc_context_restore(uc, context);

		DWORD useless;
		VirtualProtect((LPVOID)PageState->Data, 0x1000, PAGE_READWRITE, &useless); // When loading the client the memory is set to NO_ACCESS
		UEMU_CHECK("UC_MEM_WRITE",uc_mem_write(uc, EMULATION_DECRYPTION_BASE_DATA_ADDRESS, PageState->Data, 0x1000)); // Write the encrypted page data
	}

	uc_err StartEmulation(uc_engine* uc)
	{
		uintptr_t RIP;
		uc_reg_read(uc, UC_X86_REG_RIP, &RIP);

		//Emulation::PrintCpuContext(uc);

		uc_err status = uc_emu_start(uc, RIP, RIP + 0x10000, 0, 0);
		
		return status;
	}

	void InitializeDecryptionEmulation(PEFile* loaderPE,uc_engine** uc, uintptr_t* DecryptionKeyArrayAddy, DumpedRegisters& DumpedRegisters)
	{
		auto decryptionRange = Dumper::FetchEmulationRange(loaderPE);
		Logger::Debug("Emulation Range: %p to %p", decryptionRange.first, decryptionRange.second);

		auto DecryptionKeyOffset = PageDecryptorCore::Dumper::FetchDecryptionKeyOffset(loaderPE, decryptionRange.first);
		*DecryptionKeyArrayAddy = DecryptionKeyOffset.second;
		PageDecryptorCore::Dumper::DumpRegisters(decryptionRange.first, DecryptionKeyOffset.first, DumpedRegisters);

		*uc = SetupEmulation();

		// Roblox started accessing values from .rdata.. so we now need to map the whole dll for a proper emulation.
		// NVM! WE are going to bridge inside the memory hook
		auto code = loaderPE->GetSectionRange(".byfron");
		
		UEMU_CHECK("UC_MEM_MAP", uc_mem_map(*uc, code.first, (code.second - code.first) & 0xFFFFFFFFFFFFF000uLL, UC_PROT_ALL));
		UEMU_CHECK("UC_MEM_WRITE", uc_mem_write(*uc, code.first, (const void*)code.first, (code.second - code.first) & 0xFFFFFFFFFFFFF000uLL));
		

		/*
		UEMU_CHECK("UC_MEM_MAP", uc_mem_map(*uc, (uint64_t)loaderPE->GetBase(), (loaderPE->GetEnd() - (uintptr_t)loaderPE->GetBase()) & 0xFFFFFFFFFFFFF000uLL, UC_PROT_ALL));
		UEMU_CHECK("UC_MEM_WRITE", uc_mem_write(*uc, (uint64_t)loaderPE->GetBase(), loaderPE->GetBase(), (loaderPE->GetEnd() - (uintptr_t)loaderPE->GetBase()) & 0xFFFFFFFFFFFFF000uLL));
		*/

		// NVM! WE are going to bridge inside the memory hook
		
		UEMU_CHECK("UC_REG_WRITE",uc_reg_write(*uc, UC_X86_REG_RIP, &decryptionRange.first));
		UEMU_CHECK("UC_MEM_WRITE",uc_mem_write(*uc, decryptionRange.second, "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC", 8));
		
		UEMU_CHECK("UC_MEM_MAP", uc_mem_map(*uc, EMULATION_DECRYPTION_BASE_DATA_ADDRESS, 0x1000, UC_PROT_ALL)); // Map the encrypted page data

		//MapDecryptionPrologue(*uc, decryptionRange.first, decryptionRange.second);
	}

	// tell me one developer from this com that can work on his own without any help or sources or blogs btw

	void hook_mem(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data) {
		if (type == UC_MEM_WRITE) {
			//printf("SEXWRITE %s\n",user_data);
			Emulation::PrintCpuContext(uc);
		}
		if (type == UC_MEM_READ) {
			//printf("SEXREAD %s\n", user_data);
			Emulation::PrintCpuContext(uc);
		}
	}

	// We expect a already initialized uc_engine and a valid DumpedRegisters
	void StartDecryptionEmulation(uc_engine* uc, DumpedRegisters* Registers, PageDecryptionState* PageState)
	{
		SetupEmulationContext(uc, Registers, PageState);

		// THE FOLLOWING LINES ARE VERY SPECIAL
		// I DO NOT GOT ANY IDEA WHY THE FUCK SETTING XMM7 MAKES IT WORK..
		// XMM7 DOES NOT GET ACCESSED ANYWHERE IN THE DECRYPTION PROCESS
		// I ASSUME ITS A UNICORN EMU BUG
		//auto IDFK = _mm_set_epi64x(0xffffffffffffffff, 0xffffffffffffffff);
		//uc_reg_write(uc, UC_X86_REG_XMM7, &IDFK);
		// !NVM! it was getting used but only in a FEW page ranges ^^
		// MOVED INTO SetupEmulationContext

		// Debugging
		//uc_hook mem_hook;
		//uc_hook_add(uc, &mem_hook, UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_mem, (void*)"MEOW", EMULATION_DECRYPTION_BASE_DATA_ADDRESS, EMULATION_DECRYPTION_BASE_DATA_ADDRESS + 0x1000);

		uintptr_t RIP;
		uc_reg_read(uc, UC_X86_REG_RIP, &RIP);

		uc_err status = StartEmulation(uc);
		if (status == UC_ERR_EXCEPTION)
		{
			uc_reg_write(uc, UC_X86_REG_RIP, &RIP);

			//Emulation::PrintCpuContext(uc);
			// What we expect!
			char newData[0x1000];
			uc_mem_read(uc, EMULATION_DECRYPTION_BASE_DATA_ADDRESS, newData, 0x1000);
			memcpy(PageState->Data, newData, 0x1000); // Copy the decrypted data back to the original location
		}
		else
		{
			Emulation::PrintCpuContext(uc);
			throw std::runtime_error("Emulation failed with error: " + std::string(uc_strerror(status)));
		}
	}
}

// astril is a cutieee <333