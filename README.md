# Brochacha20
A fully static Roblox Client Decryptor

<img width="985" height="265" alt="image" src="https://github.com/user-attachments/assets/b459bb6b-cde6-462f-aa7e-a49b7c6efc92" />

# How to Use
1. Download newest Build from Release Tab (I recommend downloading the UPX Packed version cuz its way smaller)
2. Run the Brochacha20.exe with your Roblox Directory as an argument (Example: Brochacha20.exe C:\Roblox\Versions\version-9bf2d7ce6a0345d5)
3. [OPTIONAL] Set output directory via -o (Example: Brochacha20.exe C:\Roblox\Dumps\RobloxDump.bin)
4. Enjoy ^^

# Options
-s,-silent   : No logging   
-o,--output  : Decrypted output

# Issues
When an Issue occurs, you can open an Issue report on Github providing your Console Log and the Roblox Version you tried to Decrypt (via hash like version-225e87fdb7254f64)       
WHEN It's very important and you REALLY need it to work you can also contact me via discord: @mrnasec

# How to Build
1. Download Repo
2. Open solution with Visual Studio
3. Get a compiled version of the UnicornEmu library
4. Place the .lib into Brochacha20\libs\unicorn\lib\unicorn.lib
5. Build as Release/Debug using Visual Studio
6. Enjoy :3

# How Does it Work?

```
Brief Explanation about Hyperion's Runtime Page decryption (FULLY ANALYZED BY NASEC)

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

All that above me is what Roblox internally does to compute the OffsetKey.
At the end the OffsetKey is just PageRVA shifted by 32 bits.

Decryption:

So we require for the Hyperion's ChaCha20 decryption the following values:

    OffsetKey
    NOffsetKey
    DecryptionKey1
    DecryptionKey2

They will be fed to the ChaCha20 decryption function to start the decryption process
```

# Contact
discord: @mrnasec
