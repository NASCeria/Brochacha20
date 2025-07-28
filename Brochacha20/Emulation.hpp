// Little wrapper ^^ 


#include <iostream>

#include <unicorn/unicorn.h>
#include "Zydis/Zydis.h"

// Helper functions
namespace Zydis
{
	struct ZydisDecodedFullInstruction
	{
		ZydisDecodedInstruction inst;
		ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
		uintptr_t offset;
	};

	ZydisDecodedFullInstruction Disassmemble(uintptr_t addy)
	{
		ZydisDecoder decoder;
		ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

		ZydisDecodedFullInstruction instruction;
		instruction.offset = addy;
		ZydisDecoderDecodeFull(&decoder, (const void*)addy, 0x10, &instruction.inst, (ZydisDecodedOperand*)&instruction.operands);
		return instruction;
	}

	std::string FormatInstruction(ZydisDecodedFullInstruction instruction)
	{
		char buffer[256];
		ZydisFormatter formatter;
		ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
		ZydisFormatterFormatInstruction(
			&formatter,
			&instruction.inst,
			instruction.operands,
			instruction.inst.operand_count,
			buffer,
			sizeof(buffer),
			instruction.offset,
			ZYAN_NULL);
		return std::string(buffer);
	}

}

#define UEMU_CHECK(func,err) \
	if (err != UC_ERR_OK) { \
		std::printf("%u %s\n", __LINE__, __FILE__); \
		throw std::runtime_error(std::string("Emulation error in ") + func + " " + uc_strerror(err)); \
	}

namespace Emulation
{
	uc_x86_reg ZydisReg2Uc(ZydisRegister_ reg)
	{
		switch (reg)
		{
		case ZYDIS_REGISTER_RIP: return UC_X86_REG_RIP;
		case ZYDIS_REGISTER_RBP: return UC_X86_REG_RBP;
		case ZYDIS_REGISTER_RSP: return UC_X86_REG_RSP;
		case ZYDIS_REGISTER_RAX: return UC_X86_REG_RAX;
		case ZYDIS_REGISTER_RBX: return UC_X86_REG_RBX;
		case ZYDIS_REGISTER_RCX: return UC_X86_REG_RCX;
		case ZYDIS_REGISTER_RDX: return UC_X86_REG_RDX;
		case ZYDIS_REGISTER_RSI: return UC_X86_REG_RSI;
		case ZYDIS_REGISTER_RDI: return UC_X86_REG_RDI;
		case ZYDIS_REGISTER_R8: return UC_X86_REG_R8;
		case ZYDIS_REGISTER_R9: return UC_X86_REG_R9;
		case ZYDIS_REGISTER_R10: return UC_X86_REG_R10;
		case ZYDIS_REGISTER_R11: return UC_X86_REG_R11;
		case ZYDIS_REGISTER_R12: return UC_X86_REG_R12;
		case ZYDIS_REGISTER_R13: return UC_X86_REG_R13;
		case ZYDIS_REGISTER_R14: return UC_X86_REG_R14;
		case ZYDIS_REGISTER_R15: return UC_X86_REG_R15;
		case ZYDIS_REGISTER_XMM1: return UC_X86_REG_XMM1;
		case ZYDIS_REGISTER_XMM2: return UC_X86_REG_XMM2;
		case ZYDIS_REGISTER_XMM3: return UC_X86_REG_XMM3;
		case ZYDIS_REGISTER_XMM4: return UC_X86_REG_XMM4;
		case ZYDIS_REGISTER_XMM5: return UC_X86_REG_XMM5;
		case ZYDIS_REGISTER_XMM6: return UC_X86_REG_XMM6;
		case ZYDIS_REGISTER_XMM7: return UC_X86_REG_XMM7;
		case ZYDIS_REGISTER_XMM8: return UC_X86_REG_XMM8;
		case ZYDIS_REGISTER_XMM9: return UC_X86_REG_XMM9;
		case ZYDIS_REGISTER_XMM10: return UC_X86_REG_XMM10;
		case ZYDIS_REGISTER_XMM11: return UC_X86_REG_XMM11;
		case ZYDIS_REGISTER_XMM12: return UC_X86_REG_XMM12;
		case ZYDIS_REGISTER_XMM13: return UC_X86_REG_XMM13;
		case ZYDIS_REGISTER_XMM14: return UC_X86_REG_XMM14;
		case ZYDIS_REGISTER_XMM15: return UC_X86_REG_XMM15;
		case ZYDIS_REGISTER_XMM16: return UC_X86_REG_XMM16;
		case ZYDIS_REGISTER_XMM17: return UC_X86_REG_XMM17;
		case ZYDIS_REGISTER_XMM18: return UC_X86_REG_XMM18;
		case ZYDIS_REGISTER_XMM19: return UC_X86_REG_XMM19;
		case ZYDIS_REGISTER_XMM20: return UC_X86_REG_XMM20;
		case ZYDIS_REGISTER_XMM21: return UC_X86_REG_XMM21;
		case ZYDIS_REGISTER_XMM22: return UC_X86_REG_XMM22;
		case ZYDIS_REGISTER_XMM23: return UC_X86_REG_XMM23;
		case ZYDIS_REGISTER_XMM24: return UC_X86_REG_XMM24;
		case ZYDIS_REGISTER_XMM25: return UC_X86_REG_XMM25;
		case ZYDIS_REGISTER_XMM26: return UC_X86_REG_XMM26;
		case ZYDIS_REGISTER_XMM27: return UC_X86_REG_XMM27;
		case ZYDIS_REGISTER_XMM28: return UC_X86_REG_XMM28;
		case ZYDIS_REGISTER_XMM29: return UC_X86_REG_XMM29;
		case ZYDIS_REGISTER_XMM30: return UC_X86_REG_XMM30;
		case ZYDIS_REGISTER_XMM31: return UC_X86_REG_XMM31;
		default:
			throw std::runtime_error("Unsupported register");
		}
	}

	void Test()
	{
		uc_engine* uc;
		uc_open(UC_ARCH_ARM64, UC_MODE_64, &uc);

		uc_mem_map(uc, 0x1000, 0x1000, UC_PROT_ALL);
		uc_mem_write(uc, 0x1000, "\xC3\x00\x00\x00", 4);

		uc_emu_start(uc, 0x1000, 0x1004, 0, 1);

	}

	void PrintCpuContext(uc_engine* uc)
	{
		std::vector<std::pair<std::string, uc_x86_reg>> regs = {
			{"RAX", UC_X86_REG_RAX},
			{"RBX", UC_X86_REG_RBX},
			{"RCX", UC_X86_REG_RCX},
			{"RDX", UC_X86_REG_RDX},
			{"RSI", UC_X86_REG_RSI},
			{"RDI", UC_X86_REG_RDI},
			{"RBP", UC_X86_REG_RBP},
			{"RSP", UC_X86_REG_RSP},
			{"RIP", UC_X86_REG_RIP},
			{"R8",  UC_X86_REG_R8},
			{"R9",  UC_X86_REG_R9},
			{"R10", UC_X86_REG_R10},
			{"R11", UC_X86_REG_R11},
			{"R12", UC_X86_REG_R12},
			{"R13", UC_X86_REG_R13},
			{"R14", UC_X86_REG_R14},
			{"R15", UC_X86_REG_R15},
			{"XMM0", UC_X86_REG_XMM0},
			{"XMM1", UC_X86_REG_XMM1},
			{"XMM2", UC_X86_REG_XMM2},
			{"XMM3", UC_X86_REG_XMM3},
			{"XMM4", UC_X86_REG_XMM4},
			{"XMM5", UC_X86_REG_XMM5},
			{"XMM6", UC_X86_REG_XMM6},
			{"XMM7", UC_X86_REG_XMM7},
			{"XMM8", UC_X86_REG_XMM8},
			{"XMM9", UC_X86_REG_XMM9},
			{"XMM10", UC_X86_REG_XMM10},
			{"XMM11", UC_X86_REG_XMM11},
			{"XMM12", UC_X86_REG_XMM12},
			{"XMM13", UC_X86_REG_XMM13},
			{"XMM14", UC_X86_REG_XMM14},
			{"XMM15", UC_X86_REG_XMM15},
		};

		for (auto reg : regs)
		{
			__m128 value = {};
			if (uc_reg_read(uc, reg.second, &value) == UC_ERR_OK)
			{
				std::cout << reg.first << " = 0x" << std::hex << value.m128_u64[1] << value.m128_u64[0] << std::endl;
			}
		}
	}

	void ClearEssentialRegisters(uc_context* context)
	{
		uint64_t zero = 0;
		uc_context_reg_write(context, UC_X86_REG_RAX, &zero);
		uc_context_reg_write(context, UC_X86_REG_RBX, &zero);
		uc_context_reg_write(context, UC_X86_REG_RCX, &zero);
		uc_context_reg_write(context, UC_X86_REG_RDX, &zero);
		uc_context_reg_write(context, UC_X86_REG_RSI, &zero);
		uc_context_reg_write(context, UC_X86_REG_RDI, &zero);
		uc_context_reg_write(context, UC_X86_REG_R10, &zero);
		uc_context_reg_write(context, UC_X86_REG_R11, &zero);
		uc_context_reg_write(context, UC_X86_REG_R12, &zero);
		uc_context_reg_write(context, UC_X86_REG_R13, &zero);
		uc_context_reg_write(context, UC_X86_REG_R14, &zero);

	}

	void StartEmulation(uc_engine* uc, uint64_t start_address, uint64_t end_address, uint64_t timeout = 0)
	{
		uc_err err = uc_emu_start(uc, start_address, end_address, timeout, 0);
		if (err != UC_ERR_OK)
		{
			throw std::runtime_error("Failed to start emulation: " );
		}
	}

	void StopEmulation(uc_engine* uc)
	{
		uc_emu_stop(uc);
	}

	bool ProbeForRead(void* addy)
	{
		__try
		{
			*(char*)addy;
			return true;
		}
		__except (EXCEPTION_CONTINUE_EXECUTION)
		{
			return false;
		}
	}

	static bool hookAccessViolation(uc_engine* uc, uc_mem_type type,
		uint64_t address, int size,
		int64_t value, void* user_data)
	{
		uintptr_t RIP;
		uc_reg_read(uc, UC_X86_REG_RIP,&RIP);
		
		char insts[16] = {0};
		uc_mem_read(uc, RIP, insts, 16);

		bool legalRead = ProbeForRead((void*)address);


		if (legalRead)
		{
			uint64_t page_start = address & ~0xFFF;
			uc_mem_map(uc, page_start, 0x1000, UC_PROT_READ | UC_PROT_WRITE);
			uc_mem_write(uc, page_start, (void*)page_start, 0x1000);
			return true;
		}

		Logger::Error("ACCESS VIOLATION AT %p TRYING TO %s %p", RIP, type == UC_MEM_WRITE_UNMAPPED ? "WRITE" : type == UC_MEM_READ_UNMAPPED ? "READ" : "FETCH", address);
		Logger::Error("%s", Zydis::FormatInstruction(Zydis::Disassmemble((uintptr_t)insts)).c_str());
		uc_emu_stop(uc);


		return false;
	}

	uc_engine* SetupEmulation()
	{
		const uint64_t STACK_SIZE = 0x10000; // 64kb
		const uint64_t STACK_BASE = 0x200000;
		const uint64_t STACK_TOP = STACK_BASE + STACK_SIZE;

		uc_engine* uc;
		UEMU_CHECK("UC_OPEN", uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
		UEMU_CHECK("UC_MEM_MAP", uc_mem_map(uc, STACK_BASE, STACK_SIZE, UC_PROT_ALL));
		UEMU_CHECK("UC_REG_WRITE",uc_reg_write(uc, UC_X86_REG_RSP, &STACK_TOP));
		UEMU_CHECK("UC_REG_WRITE", uc_reg_write(uc, UC_X86_REG_RBP, &STACK_BASE));

		uc_hook mem_hook;
		uc_hook_add(uc, &mem_hook, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hookAccessViolation, 0, 1, 0);

		return uc;
	}

	uc_err StepEmulation(uc_engine* uc)
	{
		uint64_t rip;
		uc_reg_read(uc, UC_X86_REG_RIP, &rip);
		return uc_emu_start(uc, rip, rip + 0x10, 0, 1);
	}
}