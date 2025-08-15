#pragma once
#include <cstdint>

// hmmm how do we call it?? sub branch resolver,,,, int3 stub resolver,, ,jcc resolver??? int3 jcc branch resolver?????

namespace JCCResolver
{
	// Hyperion handles 16 Jcc's
	enum JCC
	{
		JO = 0,
		JNO,
		JC,
		JNC,
		JZ,
		JNZ,
		JBE,
		JNBE,
		JS = 8,
		JNS,
		JP,
		SPECIAL,
		JL,
		JGE,
		JLE,
		JG,
	};

	struct Int3Stub
	{
		uint32_t DestinationBranchDelta;
		uint32_t StubAddress;
		JCC JccType;
	};

	struct Int3StubTables
	{
		uint32_t* StubArray;
		uint8_t* JccTypeArray;
		uint8_t* DestBranchArray;
	};;

	static const char* JccTypeToString(JCC jcc)
	{
		switch (jcc)
		{
		case JO:      return "JO";      
		case JNO:     return "JNO";     
		case JC:      return "JC";      
		case JNC:     return "JNC";     
		case JZ:      return "JZ";      
		case JNZ:     return "JNZ";     
		case JBE:     return "JBE";     
		case JNBE:    return "JNBE";    
		case JS:      return "JS";      
		case JNS:     return "JNS";
		case JP:      return "JP";
		case SPECIAL: return "SPECIAL";
		case JL:      return "JL";
		case JGE:     return "JGE";
		case JLE:     return "JLE";     
		case JG:      return "JG";
		default:      return "UNKNOWN";
		}
	}

	static void PatchJCC(JCC JCC, char* location, uint32_t rel, bool x = false)
	{
		char opcode = 0;
		switch (JCC)
		{
		case JCCResolver::JO:
			opcode = x ? 0x70 : 0x80;
			break;
		case JCCResolver::JNO:
			opcode = x ? 0x71 : 0x81;
			break;
		case JCCResolver::JC:
			opcode = x ? 0x72 : 0x82;
			break;
		case JCCResolver::JNC:
			opcode = x ? 0x73 : 0x83;
			break;
		case JCCResolver::JZ:
			opcode = x ? 0x74 : 0x85;
			break;
		case JCCResolver::JNZ:
			opcode = x ? 0x75 : 0x86;
			break;
		case JCCResolver::JBE:
			opcode = x ? 0x76 : 0x86;
			break;
		case JCCResolver::JNBE:
			opcode = x ? 0x77 : 0x87;
			break;
		case JCCResolver::JS:
			opcode = x ? 0x78 : 0x88;
			break;
		case JCCResolver::JNS:
			opcode = x ? 0x79 : 0x89;
			break;
		case JCCResolver::JP:
			opcode = x ? 0x7A : 0x8A;
			break;
		case JCCResolver::SPECIAL:
			break;
		case JCCResolver::JL:
			opcode = x ? 0x7C : 0x8C;
			break;
		case JCCResolver::JGE:
			opcode = x ? 0x7D : 0x8D;
			break;
		case JCCResolver::JLE:
			opcode = x ? 0x7E : 0x8E;
			break;
		case JCCResolver::JG:
			opcode = x ? 0x7F : 0x8F;
			break;
		default:
			break;
		}

		if (x)
		{
			location[0] = opcode;
			*(uint8_t*)&location[1] = rel;
		}
		else
		{
			location[0] = 0x0F;
			location[1] = opcode;
			*(uint32_t*)&location[2] = rel;
		}
	}

	static Int3Stub* ResolveJcc(Int3StubTables* Arrays, uint32_t Index)
	{
		Int3Stub* Stub = new Int3Stub();

		Stub->StubAddress = Arrays->StubArray[Index];
		Stub->JccType = (JCC)((Arrays->JccTypeArray[Index >> 1] >> ((Index * 4) & 4)) & 0xF);
		Stub->DestinationBranchDelta = Arrays->DestBranchArray[Index] + 2;

		return Stub;
	}

	// XClusive for JCCs that arent short jcc's
	static Int3Stub* ResolveJccX(Int3StubTables* Arrays, uint32_t Index)
	{
		Int3Stub* Stub = new Int3Stub();

		Stub->StubAddress = Arrays->StubArray[Index];
		Stub->JccType = (JCC)((Arrays->JccTypeArray[Index >> 1] >> ((Index * 4) & 4)) & 0xF);
		Stub->DestinationBranchDelta = ((uint32_t*)Arrays->DestBranchArray)[Index] + 6;

		return Stub;
	}

	static Int3StubTables* CreateInt3StubTables(uint32_t* StubArray, uint8_t* JccTypeArray, uint8_t* DestBranchArray)
	{
		Int3StubTables* Tables = new Int3StubTables();
		Tables->StubArray = StubArray;
		Tables->JccTypeArray = JccTypeArray;
		Tables->DestBranchArray = DestBranchArray;
		return Tables;
	}

	static int GetInt3StubSize(uint32_t* StubArray)
	{
		uint32_t lastEntry = 0;
		int i = 0;

		while (StubArray[i] > lastEntry)
		{
			lastEntry = StubArray[i];
			i++;
		}

		return i;
	}
}

