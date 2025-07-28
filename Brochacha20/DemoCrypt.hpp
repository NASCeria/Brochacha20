// DemoCrypt.hpp 
// EVERYTHING HERE IS FROM MY OWN RESEARCH(nasec) 
// This file is a kind of PoC of being able to decrypt the Roblox client using Hyperion's runtime decryption


/* 
        Brief Explanation about Hyperion's runtime Page decryption

        Offsets:

        DecryptionKeyArray Inside RobloxPlayerBeta.dll


        Operations:

        Part1:

		PageRVA = (ExceptionAddress & 0xFFFFFFFFFFFFF000uLL) - RobloxClientBase
        PageId  = PageRVA >> 12
        DecryptionKeyOffset = (PageId % 0x2004) * 32
		DecryptionKey1 = *(uint128_t*)(DecryptionKeyArray + DecryptionKeyOffset)
        DecryptionKey2 = *(uint128_t*)(DecryptionKeyArray + DecryptionKeyOffset + 16)

        Part2:

        PageDecryptionBlockKeysBase # Gathered from Allocator function
        PageRVA = (ExceptionAddress & 0xFFFFFFFFFFFFF000uLL) - RobloxClientBase
        PageDecryptionKeyBlockOffset = 344 * (PageRVA >> 12) (OR 344 * PageId)
        CurrentPageKeyBlock = PageDecryptionBlockKeysBase + PageDecryptionKeyBlockOffset
        PageDecryKey1 = *(uint8_t*)(CurrentPageKeyBlock + 158)

        v2853 = *(BYTE *)(CurrentPageKeyBlock + 197) ^ __ROL1__(*(BYTE *)(CurrentPageKeyBlock + 4 * PageDecryKey1 + 174),2);
        v2854 = *(BYTE *)(CurrentPageKeyBlock + 198) ^ __ROL1__(*(BYTE *)(CurrentPageKeyBlock + 4 * PageDecryKey1 + 175),2);
        v2855 = *(BYTE *)(CurrentPageKeyBlock + 199) ^ __ROL1__(*(BYTE *)(CurrentPageKeyBlock + 4 * PageDecryKey1 + 176),2);
        v2856 = *(BYTE *)(CurrentPageKeyBlock + 200) ^ __ROL1__(*(BYTE *)(CurrentPageKeyBlock + 4 * PageDecryKey1 + 177),2);

        OffsetKey1 = (v2856 << 24) | (v2855 << 16) | (v2854 << 8) | v2853;
        OffsetKey2 = ((((DWORD)-RobloxPlayerExeBase + ExceptionAddress & 0x7FFF000) >> 12) & 0x7FFF) << 44 (OR PageRVA << 32 :3)

        OffsetKey = OffsetKey1 + OffsetKey2
		NOffsetKey = ~OffsetKey


        Decryption:

        So we require for the Hyperion's ChaCha20 decryption the following values:

            OffsetKey
            NOffsetKey
            DecryptionKey1
            DecryptionKey2

        They will be fed to the ChaCha20 decryption function to start the decryption process
*/



#include <Windows.h>
#include <intrin.h>

#include "defs.h"

// From Hex Rays Decompiler output
uintptr_t AllocateKeyBlocks()
{
    __int64 v0; // rbp
    __int64 allocatedDecryptionKeys; // rcx
    __int64 iter; // r8
    __int64 allocatedDecryptionKeysBuff; // rdi
    __int64 result; // rax
    __int64 currentBlock; // rbx
    __int64 v6; // rdx
    __int64 i; // rax
    __int64 v8; // rdx
    __int64 v9; // rdx
    __int64 v10; // rdx
    unsigned __int16 v11; // ax
    __int64 v12; // rdx
    __int64 j; // rax
    __int64 v14; // rdx
    __int64 v15; // rdx
    __int64 v16; // rdx
    unsigned __int16 v17; // ax
    __int64 v18; // rdx
    __int64 k; // rax
    __int64 v20; // rdx
    __int64 v21; // rdx
    __int64 v22; // rdx
    unsigned __int16 v23; // ax
    __int64 v24; // rdx
    __int64 m; // rax
    __int64 v26; // rdx
    __int64 v27; // rdx
    unsigned __int16 v28; // ax
    __int64 v29; // rdx
    __int64 n; // rax
    __int64 v31; // rdx
    __int64 v32; // rdx
    __int64 v33; // rdx

    allocatedDecryptionKeys = (uintptr_t)malloc(0x9F4C20LL);
    iter = 0LL;
    allocatedDecryptionKeysBuff = allocatedDecryptionKeys;
    do
    {
        currentBlock = allocatedDecryptionKeys + iter;
        *(_BYTE*)(allocatedDecryptionKeys + iter + 32) = 0;
        *(_DWORD*)(allocatedDecryptionKeys + iter + 34) = 0;
        *(_WORD*)(allocatedDecryptionKeys + iter + 38) = 0;
        *(_BYTE*)(allocatedDecryptionKeys + iter + 50) = 0;
        *(_OWORD*)(allocatedDecryptionKeys + iter) = { 0LL,0LL };
        v6 = 0x14FFC17CA866FD9LL * __rdtsc() + 1;
        for (i = 19LL; i != 55; i += 4LL)
        {
            v8 = 0x14FFC17CA866FD9LL * v6 + 1;
            *(_BYTE*)(allocatedDecryptionKeysBuff + i - 3) = BYTE4(v8);
            v9 = 0x14FFC17CA866FD9LL * v8 + 1;
            *(_BYTE*)(allocatedDecryptionKeysBuff + i - 2) = BYTE4(v9);
            v10 = 0x14FFC17CA866FD9LL * v9 + 1;
            *(_BYTE*)(allocatedDecryptionKeysBuff + i - 1) = BYTE4(v10);
            v6 = 0x14FFC17CA866FD9LL * v10 + 1;
            *(_BYTE*)(allocatedDecryptionKeysBuff + i) = BYTE4(v6);
        }
        v11 = -3 * (((10923 * ((unsigned int)*(unsigned __int8*)(currentBlock + 32) + 1)) >> 15) & 0xFFFE)
            + *(unsigned __int8*)(currentBlock + 32)
            + 1;
        *(_BYTE*)(currentBlock + v11 + 34) = __ROL1__(*(_BYTE*)(currentBlock + 50) ^ 0xFC, 6);
        *(_BYTE*)(currentBlock + 32) = v11;
        *(_BYTE*)(currentBlock + 67) = 0;
        *(_OWORD*)(currentBlock + 74) = { 0LL,0LL };
        *(_OWORD*)(currentBlock + 90) = { 0LL,0LL };
        *(_QWORD*)(currentBlock + 106) = 0LL;
        *(_QWORD*)(currentBlock + 126) = 0LL;
        v12 = 0x5F82304552A4BC5LL * __rdtsc() + 11;
        for (j = 55LL; ; j += 4LL)
        {
            v14 = 0x5F82304552A4BC5LL * v12 + 11;
            *(_BYTE*)(allocatedDecryptionKeysBuff + j - 3) = BYTE4(v14);
            if (j == 139)
                break;
            v15 = 0x5F82304552A4BC5LL * v14 + 11;
            *(_BYTE*)(allocatedDecryptionKeysBuff + j - 2) = BYTE4(v15);
            v16 = 0x5F82304552A4BC5LL * v15 + 11;
            *(_BYTE*)(allocatedDecryptionKeysBuff + j - 1) = BYTE4(v16);
            v12 = 0x5F82304552A4BC5LL * v16 + 11;
            *(_BYTE*)(allocatedDecryptionKeysBuff + j) = BYTE4(v12);
        }
        v17 = -5 * ((13108 * ((unsigned int)*(unsigned __int8*)(currentBlock + 67) + 1)) >> 16)
            + *(unsigned __int8*)(currentBlock + 67)
            + 1;
        *(_BYTE*)(currentBlock + 8LL * v17 + 74) = -1;
        *(_BYTE*)(currentBlock + 8LL * v17 + 75) = -1;
        *(_BYTE*)(currentBlock + 8LL * v17 + 76) = -1;
        *(_BYTE*)(currentBlock + 8LL * v17 + 77) = -1;
        *(_BYTE*)(currentBlock + 8LL * v17 + 78) = -1;
        *(_BYTE*)(currentBlock + 8LL * v17 + 79) = -1;
        *(_BYTE*)(currentBlock + 8LL * v17 + 80) = -1;
        *(_BYTE*)(currentBlock + 8LL * v17 + 81) = -1;
        *(_BYTE*)(currentBlock + 67) = v17;
        *(_BYTE*)(currentBlock + 158) = 0;
        *(_OWORD*)(currentBlock + 174) = { 0LL,0LL };
        *(_DWORD*)(currentBlock + 190) = 0;
        *(_DWORD*)(currentBlock + 197) = 0;
        v18 = 0x1D03B30FCFABD81LL * __rdtsc() + 11;
        for (k = 148LL; ; k += 4LL)
        {
            v20 = 0x1D03B30FCFABD81LL * v18 + 11;
            *(_BYTE*)(allocatedDecryptionKeysBuff + k - 3) = BYTE4(v20);
            v21 = 0x1D03B30FCFABD81LL * v20 + 11;
            *(_BYTE*)(allocatedDecryptionKeysBuff + k - 2) = BYTE4(v21);
            v22 = 0x1D03B30FCFABD81LL * v21 + 11;
            *(_BYTE*)(allocatedDecryptionKeysBuff + k - 1) = BYTE4(v22);
            if (k == 204)
                break;
            v18 = 0x1D03B30FCFABD81LL * v22 + 11;
            *(_BYTE*)(allocatedDecryptionKeysBuff + k) = BYTE4(v18);
        }
        v23 = -5 * ((13108 * ((unsigned int)*(unsigned __int8*)(currentBlock + 158) + 1)) >> 16)
            + *(unsigned __int8*)(currentBlock + 158)
            + 1;
        *(_BYTE*)(currentBlock + 4LL * v23 + 174) = __ROL1__(*(_BYTE*)(currentBlock + 197), 6);
        *(_BYTE*)(currentBlock + 4LL * v23 + 175) = __ROL1__(*(_BYTE*)(currentBlock + 198), 6);
        *(_BYTE*)(currentBlock + 4LL * v23 + 176) = __ROL1__(*(_BYTE*)(currentBlock + 199), 6);
        *(_BYTE*)(currentBlock + 4LL * v23 + 177) = __ROL1__(*(_BYTE*)(currentBlock + 200), 6);
        *(_BYTE*)(currentBlock + 158) = v23;
        *(_BYTE*)(currentBlock + 209) = 0;
        *(_OWORD*)(currentBlock + 220) = { 0LL,0LL };
        *(_DWORD*)(currentBlock + 236) = 0;
        *(_DWORD*)(currentBlock + 253) = 0;
        v24 = 0x1D03B30FCFABD81LL * __rdtsc() + 11;
        for (m = 211LL; m != 262; m += 3LL)
        {
            v26 = 0x1D03B30FCFABD81LL * v24 + 11;
            *(_BYTE*)(allocatedDecryptionKeysBuff + m - 2) = BYTE4(v26);
            v27 = 0x1D03B30FCFABD81LL * v26 + 11;
            *(_BYTE*)(allocatedDecryptionKeysBuff + m - 1) = BYTE4(v27);
            v24 = 0x1D03B30FCFABD81LL * v27 + 11;
            *(_BYTE*)(allocatedDecryptionKeysBuff + m) = BYTE4(v24);
        }
        v28 = -5 * ((13108 * ((unsigned int)*(unsigned __int8*)(currentBlock + 209) + 1)) >> 16)
            + *(unsigned __int8*)(currentBlock + 209)
            + 1;
        *(_BYTE*)(currentBlock + 4LL * v28 + 220) = __ROL1__(~*(_BYTE*)(currentBlock + 253), 5);
        *(_BYTE*)(currentBlock + 4LL * v28 + 221) = __ROL1__(~*(_BYTE*)(currentBlock + 254), 5);
        *(_BYTE*)(currentBlock + 4LL * v28 + 222) = __ROL1__(~*(_BYTE*)(currentBlock + 255), 5);
        *(_BYTE*)(currentBlock + 4LL * v28 + 223) = __ROL1__(~*(_BYTE*)(currentBlock + 256), 5);
        *(_BYTE*)(currentBlock + 209) = v28;
        *(_BYTE*)(currentBlock + 285) = 0;
        *(_OWORD*)(currentBlock + 292) = { 0LL,0LL };
        *(_OWORD*)(currentBlock + 308) = { 0LL,0LL };
        *(_QWORD*)(currentBlock + 335) = 0LL;
        v29 = 0xF09E1EA0B32D668LL * __rdtsc() + 11;
        for (n = 273LL; ; n += 4LL)
        {
            v31 = 0xF09E1EA0B32D668LL * v29 + 11;
            *(_BYTE*)(allocatedDecryptionKeysBuff + n - 3) = BYTE4(v31);
            if (n == 345)
                break;
            v32 = 0xF09E1EA0B32D668LL * v31 + 11;
            *(_BYTE*)(allocatedDecryptionKeysBuff + n - 2) = BYTE4(v32);
            v33 = 0xF09E1EA0B32D668LL * v32 + 11;
            *(_BYTE*)(allocatedDecryptionKeysBuff + n - 1) = BYTE4(v33);
            v29 = 0xF09E1EA0B32D668LL * v33 + 11;
            *(_BYTE*)(allocatedDecryptionKeysBuff + n) = BYTE4(v29);
        }
        result = (*(_BYTE*)(currentBlock + 285) + 1) & 3;
        *(_BYTE*)(currentBlock + 8 * result + 292) = ~*(_BYTE*)(currentBlock + 335);
        *(_BYTE*)(currentBlock + 8 * result + 293) = ~*(_BYTE*)(currentBlock + 336);
        *(_BYTE*)(currentBlock + 8 * result + 294) = ~*(_BYTE*)(currentBlock + 337);
        *(_BYTE*)(currentBlock + 8 * result + 295) = ~*(_BYTE*)(currentBlock + 338);
        *(_BYTE*)(currentBlock + 8 * result + 296) = ~*(_BYTE*)(currentBlock + 339);
        *(_BYTE*)(currentBlock + 8 * result + 297) = ~*(_BYTE*)(currentBlock + 340);
        *(_BYTE*)(currentBlock + 8 * result + 298) = ~*(_BYTE*)(currentBlock + 341);
        *(_BYTE*)(currentBlock + 8 * result + 299) = ~*(_BYTE*)(currentBlock + 342);
        *(_BYTE*)(currentBlock + 285) = result;
        iter += 344LL;
        allocatedDecryptionKeysBuff += 344LL;
    } while (iter != 0x9F4C20);

    return allocatedDecryptionKeys;
}


// A typical PageRVA looks like this: 0111 B000
uint64_t CalculateOffsetKey(uint64_t PageRVA, uintptr_t KeyBlock)
{
    uint8_t PageDecryKey1 = *(uint8_t*)(KeyBlock + 158);

    uint8_t v2853 = *(BYTE*)(KeyBlock + 197) ^ __ROL1__(*(BYTE*)(KeyBlock + 4 * PageDecryKey1 + 174), 2);
    uint8_t v2854 = *(BYTE*)(KeyBlock + 198) ^ __ROL1__(*(BYTE*)(KeyBlock + 4 * PageDecryKey1 + 175), 2);
    uint8_t v2855 = *(BYTE*)(KeyBlock + 199) ^ __ROL1__(*(BYTE*)(KeyBlock + 4 * PageDecryKey1 + 176), 2);
    uint8_t v2856 = *(BYTE*)(KeyBlock + 200) ^ __ROL1__(*(BYTE*)(KeyBlock + 4 * PageDecryKey1 + 177), 2);

    uint64_t OffsetKey1 = (v2856 << 24) | (v2855 << 16) | (v2854 << 8) | v2853;
    uint64_t OffsetKey2 = PageRVA << 32;

    return OffsetKey1 + OffsetKey2;
}


// A typical PageId looks like this: 111B
void GetDecryptionKeys(uint32_t PageId,uintptr_t DecryptionKeyArray, __uint128 Keys[2])
{
    uint64_t DecryptionKeyOffset = (PageId % 0x2004) * 32;
    __uint128 DecryptionKey1 = *(__uint128*)(DecryptionKeyArray + DecryptionKeyOffset);
    __uint128 DecryptionKey2 = *(__uint128*)(DecryptionKeyArray + DecryptionKeyOffset + 16);

    auto mm1 = _mm_load_si128((__m128i*)(DecryptionKeyArray + DecryptionKeyOffset));
    auto mm2 = _mm_load_si128((__m128i*)(DecryptionKeyArray + DecryptionKeyOffset + 16));

	Keys[0] = DecryptionKey1;
	Keys[1] = DecryptionKey2;
}

void RChacha20Decrypt(char* Data, uint64_t OffsetKey,__uint128 Key1, __uint128 Key2)
{
	uint64_t NOffsetKey = ~OffsetKey;

    auto mNOffsetKey = _mm_set_epi64x(0, NOffsetKey);
    auto mOffsetKey = _mm_set_epi64x(0, OffsetKey);

    auto DecryptionKey1 = _mm_set_epi64x(Key1.high, Key1.low);
    auto DecryptionKey2 = _mm_set_epi64x(Key2.high, Key2.low);


    __m128i v3103 = _mm_shuffle_epi32(DecryptionKey1, 68);
    __m128i v3104 = _mm_shuffle_epi32(DecryptionKey1, 238);
    __m128i v509 = _mm_shuffle_epi32(DecryptionKey2, 238);
    __m128i v3105 =  _mm_shuffle_epi32(DecryptionKey2, 68);

    uintptr_t v3106 = OffsetKey;
    uintptr_t v3107 = NOffsetKey;
    auto v3108 = (__m128i*)(Data + 16LL);
    uint64_t v3109 = -2LL;
    do
    {
        auto v3110 = _mm_load_si128(v3108 - 1);
        auto v3111 = _mm_sub_epi64(v3103, v3110);
        auto v3112 = _mm_srli_epi64(v3111, 0x1Fu);
        auto v3113 = _mm_srli_epi64(v3104, 0x20u);
        auto v3114 = _mm_xor_si128(
            _mm_sub_epi64(
                _mm_add_epi64(
                    _mm_mul_epu32(v3112, v3104),
                    _mm_slli_epi64(
                        _mm_add_epi64(
                            _mm_mul_epu32(v3112, v3113),
                            _mm_mul_epu32(
                                _mm_srli_epi64(_mm_or_si128(_mm_slli_epi64(v3111, 0x21u), v3112), 0x20u),
                                v3104)),
                        0x20u)),
                _mm_or_si128(_mm_slli_epi64(v3110, 0x34u), _mm_srli_epi64(v3110, 0xCu))),
            *v3108);
        auto v3115 = _mm_unpacklo_epi64(_mm_set_epi64x(0,v3107), _mm_set_epi64x(0,v3106));
        auto v3116 = _mm_xor_si128(v509, v3114);
        auto v3117 = _mm_srli_epi64(v3103, 0x20u);
        auto v3118 = _mm_xor_si128(
            _mm_sub_epi64(
                _mm_add_epi64(
                    _mm_mul_epu32(v3116, v3103),
                    _mm_slli_epi64(
                        _mm_add_epi64(
                            _mm_mul_epu32(_mm_srli_epi64(v3116, 0x20u), v3103),
                            _mm_mul_epu32(v3116, v3117)),
                        0x20u)),
                _mm_or_si128(_mm_slli_epi64(v3114, 0x32u), _mm_srli_epi64(v3114, 0xEu))),
            v3110);
        auto v3119 = _mm_sub_epi64(v3118, v509);
        auto v3120 = _mm_srli_epi64(v3119, 0xFu);
        auto v3121 = _mm_xor_si128(
            _mm_xor_si128(
                _mm_or_si128(_mm_slli_epi64(v3118, 0x34u), _mm_srli_epi64(v3118, 0xCu)),
                v3114),
            _mm_add_epi64(
                _mm_mul_epu32(v3120, v509),
                _mm_slli_epi64(
                    _mm_add_epi64(
                        _mm_mul_epu32(_mm_srli_epi64(v509, 0x20u), v3120),
                        _mm_mul_epu32(
                            _mm_srli_epi64(_mm_or_si128(_mm_slli_epi64(v3119, 0x31u), v3120), 0x20u),
                            v509)),
                    0x20u)));
        auto v3122 = _mm_xor_si128(v3103, v3121);
        auto v3123 = _mm_xor_si128(
            _mm_add_epi64(
                _mm_add_epi64(
                    _mm_or_si128(_mm_slli_epi64(v3121, 0x3Au), _mm_srli_epi64(v3121, 6u)),
                    _mm_mul_epu32(v3122, v3105)),
                _mm_slli_epi64(
                    _mm_add_epi64(
                        _mm_mul_epu32(_mm_srli_epi64(v3122, 0x20u), v3105),
                        _mm_mul_epu32(_mm_srli_epi64(v3105, 0x20u), v3122)),
                    0x20u)),
            v3118);
        auto v3124 = _mm_xor_si128(v3105, v3123);
        auto v3125 = _mm_xor_si128(
            _mm_sub_epi64(
                _mm_add_epi64(
                    _mm_mul_epu32(v3124, v3104),
                    _mm_slli_epi64(
                        _mm_add_epi64(
                            _mm_mul_epu32(_mm_srli_epi64(v3124, 0x20u), v3104),
                            _mm_mul_epu32(v3113, v3124)),
                        0x20u)),
                _mm_or_si128(_mm_slli_epi64(v3123, 0x3Du), _mm_srli_epi64(v3123, 3u))),
            v3121);
        auto v3126 = _mm_add_epi64(v509, v3125);
        auto v3127 = _mm_srli_epi64(v3126, 0x17u);
        auto v511 = _mm_xor_si128(
            _mm_xor_si128(v3123, v3115),
            _mm_sub_epi64(
                _mm_add_epi64(
                    _mm_mul_epu32(v3127, v3103),
                    _mm_slli_epi64(
                        _mm_add_epi64(
                            _mm_mul_epu32(v3117, v3127),
                            _mm_mul_epu32(
                                _mm_srli_epi64(_mm_or_si128(_mm_slli_epi64(v3126, 0x29u), v3127), 0x20u),
                                v3103)),
                        0x20u)),
                _mm_or_si128(_mm_slli_epi64(v3125, 0x25u), _mm_srli_epi64(v3125, 0x1Bu))));
        v3108[-1] = v511;
        *v3108 = _mm_xor_si128(v3125, v3115);
        v3106 += 0x2000000000LL;
        v3107 -= 0x2000000000LL;
        v3109 += 2LL;
        v3108 += 2;
    } while (v3109 < 0xFE);

    /*
    __m128i* v3844 = (__m128i*)(Data + 16LL);
    uint64_t v3845 = -2LL;
    do
    {
        auto v3846 = _mm_unpacklo_epi64(
            mNOffsetKey,
            mOffsetKey);
        auto v3847 = _mm_load_si128(v3844 - 1);
        auto v3848 = _mm_add_epi64(v3513, v3847);
        auto v3849 = _mm_srli_epi64(v3848, 0x16u);
        auto v3850 = _mm_srli_epi64(v3513, 0x20u);
        auto v3851 = _mm_xor_si128(
            _mm_sub_epi64(
                _mm_add_epi64(
                    _mm_mul_epu32(v3849, v3513),
                    _mm_slli_epi64(
                        _mm_add_epi64(
                            _mm_mul_epu32(
                                v3849,
                                v3850),
                            _mm_mul_epu32(
                                _mm_srli_epi64(
                                    _mm_or_si128(
                                        _mm_slli_epi64(v3848, 0x2Au),
                                        v3849),
                                    0x20u),
                                v3513)),
                        0x20u)),
                _mm_or_si128(
                    _mm_slli_epi64(v3847, 0x3Cu),
                    _mm_srli_epi64(v3847, 4u))),
            *v3844);
        auto v3852 = _mm_add_epi64(v3514, v3851);
        auto v3853 = _mm_srli_epi64(v3852, 0x14u);
        auto v3854 = _mm_xor_si128(
            _mm_sub_epi64(
                _mm_add_epi64(
                    _mm_mul_epu32(v3853, v509),
                    _mm_slli_epi64(
                        _mm_add_epi64(
                            _mm_mul_epu32(
                                _mm_srli_epi64(
                                    v509,
                                    0x20u),
                                v3853),
                            _mm_mul_epu32(
                                _mm_srli_epi64(
                                    _mm_or_si128(
                                        _mm_slli_epi64(v3852, 0x2Cu),
                                        v3853),
                                    0x20u),
                                v509)),
                        0x20u)),
                _mm_or_si128(
                    _mm_slli_epi64(v3851, 0x32u),
                    _mm_srli_epi64(v3851, 0xEu))),
            v3847);
        auto v3855 = _mm_xor_si128(v3512, v3854);
        auto v3856 = _mm_xor_si128(
            _mm_add_epi64(
                _mm_add_epi64(
                    _mm_or_si128(
                        _mm_slli_epi64(v3854, 0x39u),
                        _mm_srli_epi64(v3854, 7u)),
                    _mm_mul_epu32(v3855, v3514)),
                _mm_slli_epi64(
                    _mm_add_epi64(
                        _mm_mul_epu32(
                            _mm_srli_epi64(
                                v3855,
                                0x20u),
                            v3514),
                        _mm_mul_epu32(
                            _mm_srli_epi64(
                                v3514,
                                0x20u),
                            v3855)),
                    0x20u)),
            v3851);
        auto v3857 = _mm_xor_si128(v3514, v3856);
        auto v3858 = _mm_xor_si128(
            _mm_xor_si128(
                _mm_srli_epi64(v3856, 5u),
                v3854),
            _mm_add_epi64(
                _mm_mul_epu32(v3857, v3512),
                _mm_slli_epi64(
                    _mm_add_epi64(
                        _mm_mul_epu32(
                            _mm_srli_epi64(
                                v3857,
                                0x20u),
                            v3512),
                        _mm_mul_epu32(
                            _mm_srli_epi64(
                                v3512,
                                0x20u),
                            v3857)),
                    0x20u)));
        auto v3859 = _mm_xor_si128(v3512, v3858);
        auto v3860 = _mm_xor_si128(
            _mm_xor_si128(
                _mm_or_si128(
                    _mm_slli_epi64(v3858, 0x39u),
                    _mm_srli_epi64(v3858, 7u)),
                v3856),
            _mm_add_epi64(
                _mm_mul_epu32(v3859, v3513),
                _mm_slli_epi64(
                    _mm_add_epi64(
                        _mm_mul_epu32(
                            _mm_srli_epi64(
                                v3859,
                                0x20u),
                            v3513),
                        _mm_mul_epu32(v3850, v3859)),
                    0x20u)));
        auto v3861 = _mm_xor_si128(
            _mm_xor_si128(v3858, v3846),
            _mm_sub_epi64(
                v3514,
                _mm_xor_si128(v3860, v509)));
        auto v511 = _mm_xor_si128(v3860, v3846);
        v3844[-1] = v3861;
        *v3844 = v511;
        //v3842 += 0x2000000000LL;
        //v3843 -= 0x2000000000LL;
        v3845 += 2LL;
        v3844 += 2;
    } while (v3845 < 0xFE);
    */
}

// Test if decryption works
void TestDecrypt()
{
    // Load both the Client and the Loader into memory

	HANDLE ClientHandle = CreateFileA("RobloxPlayerBeta.exe", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (ClientHandle == INVALID_HANDLE_VALUE)
    {
		printf("Failed to open RobloxPlayerBeta.exe %x\n",GetLastError());
        return;
    }
	HANDLE LoaderHandle = CreateFileA("RobloxPlayerBeta.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (LoaderHandle == INVALID_HANDLE_VALUE)
    {
        printf("Failed to open RobloxPlayerBeta.dll %x\n", GetLastError());
        return;
    }

	DWORD ClientSize = GetFileSize(ClientHandle,nullptr);
    char* ClientBase = (char*)malloc(ClientSize);
    if (!ReadFile(ClientHandle, ClientBase, ClientSize, nullptr, NULL))
    {
        printf("Failed to load Client into Memory %x\n", GetLastError());
        return;
    }

    DWORD LoaderSize = GetFileSize(LoaderHandle, nullptr);
    char* LoaderBase = (char*)malloc(LoaderSize);
    if (!ReadFile(LoaderHandle, LoaderBase, LoaderSize, nullptr, NULL))
    {
        printf("Failed to load Loader into Memory %x\n", GetLastError());
        return;
    }

	CloseHandle(ClientHandle);
	CloseHandle(LoaderHandle);


    uintptr_t DecryptionKeyArray = (uintptr_t)(LoaderBase + 0xFA3A0); // 0x109fa0
	uintptr_t KeyBlocks = AllocateKeyBlocks();

    uint64_t PageRVA = 0x0111B000; // 0x0111B000
	uint32_t PageId = PageRVA >> 12;

    __uint128 Keys[2];
    GetDecryptionKeys(PageId, DecryptionKeyArray, Keys);

	uintptr_t KeyBlock = KeyBlocks + (344 * PageId);
    uint64_t OffsetKey = CalculateOffsetKey(PageRVA, KeyBlock);

    char* Data = ClientBase + 0x111A600;//PageRVA;
    RChacha20Decrypt(Data, OffsetKey, Keys[0], Keys[1]);

    printf("Review decrypted Page At %p\n", Data);
    getchar(); 
}