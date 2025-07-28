// Old code uhh, im not going to revamp it
// alot shitcode.. but it works so idc?

#pragma once
#include <Windows.h>
#include <iostream>
#include <vector>

namespace Scanner
{
	inline std::vector<uintptr_t> ScanAob(uintptr_t start, uintptr_t end, const char* aob, const char* mask, int endResults = -1)
	{
		std::vector<uintptr_t> results;

		int aobSize = strlen(mask);

		for (uintptr_t i = start; i < end - aobSize; i++)
		{
			bool found = true;
			for (int j = 0; j < aobSize; j++)
			{
				if (mask[j] == 'x' && *(char*)(i + j) != aob[j])
				{
					found = false;
					break;
				}
			}
			if (found)
			{
				results.push_back(i);
				if (results.size() >= endResults)
				{
					break;
				}
			}
		}
		return results;
	}

	inline std::vector<uintptr_t> ScanPattern(uintptr_t start, uintptr_t end, std::string pattern, int endResults = -1)
	{
		size_t len = std::count(pattern.begin(), pattern.end(), ' ') + 1;
		char* mask = new char[len + 1];
		char* aob = new char[len + 1];

		ZeroMemory(mask, len + 1);
		ZeroMemory(aob, len + 1);

		for (size_t i = 0; i < len; i++)
		{
			if (pattern[i * 3] == '?')
			{
				mask[i] = '.';
				aob[i] = 0;
			}
			else
			{
				mask[i] = 'x';
				aob[i] = (char)strtol(pattern.substr(i * 3, 2).c_str(), nullptr, 16);
			}
		}

		return ScanAob(start, end, aob, mask, endResults);
	}

	// offsets off start
	inline std::vector<uintptr_t> RScanAob(uintptr_t start, uintptr_t end, const char* aob, const char* mask,int endResults = -1)
	{
		std::vector<uintptr_t> results;

		int aobSize = strlen(mask);

		for (uintptr_t i = start; i > end - aobSize; i--)
		{
			bool found = true;
			for (int j = 0; j < aobSize; j++)
			{
				if (mask[j] == 'x' && *(char*)(i + j) != aob[j])
				{
					found = false;
					break;
				}
			}
			if (found)
			{
				results.push_back(i);
				if(results.size() >= endResults)
				{
					break;
				}
			}
		}

		return results;
	}

	inline std::vector<uintptr_t> RScanPattern(uintptr_t start, uintptr_t end, std::string pattern, int endResults = -1)
	{
		size_t len = std::count(pattern.begin(), pattern.end(), ' ') + 1;
		char* mask = new char[len + 1];
		char* aob = new char[len + 1];

		ZeroMemory(mask, len + 1);
		ZeroMemory(aob, len + 1);

		for (size_t i = 0; i < len; i++)
		{
			if (pattern[i * 3] == '?')
			{
				mask[i] = '.';
				aob[i] = 0;
			}
			else
			{
				mask[i] = 'x';
				aob[i] = (char)strtol(pattern.substr(i * 3, 2).c_str(), nullptr, 16);
			}
		}

		return RScanAob(start, end, aob, mask, endResults);
	}

	// TODO: add specific section scans like string in .rdata code in .text
	inline std::vector<uintptr_t> ScanXrefs(uintptr_t start, uintptr_t end, const char* str, int endXref = 1)
	{
		char* mask = new char[strlen(str) + 2];
		ZeroMemory(mask, strlen(str) + 2);
		memset(mask, 'x', strlen(str) + 1);

		uintptr_t strPtr = ScanAob(start, end, str, mask,1)[0];
		if (strPtr == 0) throw std::exception("String not found");

		std::vector<uintptr_t> res;

		for (uintptr_t i = start; i < end - 4; i++)
		{
			if (*(int*)(i + 3) + 7 == strPtr - (i - start))
			{
				res.push_back(i - start);
				if (res.size() >= endXref)
				{
					break;
				}
			}
		}

		return res;
	}
}
