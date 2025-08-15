#pragma once

#include "PeFile.hpp"
#include "Emulation.hpp"
#include "Logger.hpp"
#include "JCCResolverCore.hpp"

// this file is using JCCResolverCore to actually resolve shit
// JCCResolverCore is more like the "base" that has shit that is always required to do this


static void ResolveAndPatchInt3Stubs(PEFile* Loader,PEFile* Client)
{
	//uintptr_t startInt3StubLogic = Loader->ScanSection(".byfron", "?? 89 ?? ?? 29 ?? B9 ?? ?? 00 00 31 D2", 1).back();

	auto Int3StubOffsetter = Loader->ScanSection(".byfron", "B9 ?? ?? 00 00 31 D2 48 8D", 2);
	uintptr_t startInt3StubLogic = Int3StubOffsetter[0];

	auto inst = Zydis::Disassemble(startInt3StubLogic);

	// [0] = StubsArray
	// [1] = JccTypeArray
	// [2] = BranchDestinationDeltaArray
	std::vector<uintptr_t> lastLEAs;
	int Int3StubSize = 0;

	while (true)
	{
		if (inst.inst.mnemonic == ZYDIS_MNEMONIC_LEA && inst.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY && inst.operands[1].mem.base == ZYDIS_REGISTER_RIP)
		{
			lastLEAs.push_back(inst.offset + inst.operands[1].mem.disp.value + inst.inst.length);
		}
		else if (Int3StubSize == 0 && inst.inst.mnemonic == ZYDIS_MNEMONIC_MOV && inst.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
		{
			Int3StubSize = inst.operands[1].imm.value.u;
		}

		if (lastLEAs.size() >= 3) break;

		inst = Zydis::Disassemble(inst.offset + inst.inst.length);
	}

	if(Int3StubSize == 0)
	{
		throw std::runtime_error("Failed to find Int3StubSize");
	}

	auto tables = JCCResolver::CreateInt3StubTables((uint32_t*)lastLEAs[0], (uint8_t*)lastLEAs[1], (uint8_t*)lastLEAs[2]);

	for (size_t i = 0; i < Int3StubSize; i++)
	{
		auto ResolvedJcc = JCCResolver::ResolveJcc(tables, i);

		PatchJCC(ResolvedJcc->JccType, (char*)(Client->GetBase() + ResolvedJcc->StubAddress), ResolvedJcc->DestinationBranchDelta - 2, true);
#ifdef DEBUG
		Logger::Debug("Resolved JCC %s at %p with destination %p", JCCResolver::JccTypeToString(ResolvedJcc->JccType), Client->GetBase() + ResolvedJcc->StubAddress, Client->GetBase() + ResolvedJcc->StubAddress + ResolvedJcc->DestinationBranchDelta);
#endif
	}

	Logger::Success("Patched 2-Byte Int3 Stubs");

	// ROBLOX HAS A SECOND ARRAY!

	startInt3StubLogic = Int3StubOffsetter[1];

	inst = Zydis::Disassemble(startInt3StubLogic);

	// [0] = StubsArray
	// [1] = JccTypeArray
	// [2] = BranchDestinationDeltaArray
	Int3StubSize = 0;

	lastLEAs.clear();

	while (true)
	{
		if (inst.inst.mnemonic == ZYDIS_MNEMONIC_LEA && inst.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY && inst.operands[1].mem.base == ZYDIS_REGISTER_RIP)
		{
			lastLEAs.push_back(inst.offset + inst.operands[1].mem.disp.value + inst.inst.length);
		}
		else if (Int3StubSize == 0 && inst.inst.mnemonic == ZYDIS_MNEMONIC_MOV && inst.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
		{
			Int3StubSize = inst.operands[1].imm.value.u;
		}

		if (lastLEAs.size() >= 3) break;

		inst = Zydis::Disassemble(inst.offset + inst.inst.length);
	}

	if (Int3StubSize == 0)
	{
		throw std::runtime_error("Failed to find Int3StubSize");
	}

	tables = JCCResolver::CreateInt3StubTables((uint32_t*)lastLEAs[0], (uint8_t*)lastLEAs[1], (uint8_t*)lastLEAs[2]);

	for (size_t i = 0; i < Int3StubSize; i++)
	{
		auto ResolvedJcc = JCCResolver::ResolveJccX(tables, i);

		if(ResolvedJcc->JccType == JCCResolver::SPECIAL)
		{
			// Special JCCs are not handled by the JCCResolverCore
			continue;
		}

		PatchJCC(ResolvedJcc->JccType, (char*)(Client->GetBase() + ResolvedJcc->StubAddress), ResolvedJcc->DestinationBranchDelta - 6, false);
#ifdef DEBUG
		Logger::Debug("Resolved JCC %s at %p with destination %p", JCCResolver::JccTypeToString(ResolvedJcc->JccType), Client->GetBase() + ResolvedJcc->StubAddress, Client->GetBase() + ResolvedJcc->StubAddress + ResolvedJcc->DestinationBranchDelta);
#endif // DEBUG

	}

	Logger::Success("Patched 6-Byte Int3 Stubs");
}