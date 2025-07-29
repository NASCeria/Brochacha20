// Created by Naseco!!! on 07/12/2025
// Brochacha20.cpp

// This code isnt the cleanest but its performant and working!
// So please dont judge me ^^

#include <iostream>

#include "CLI11.hpp"

#include "Logger.hpp"
#include "DemoCrypt.hpp"
#include "PEDecryptor.hpp"
#include "PEDumper.hpp"

#define BROCHACHA_VERSION "v1.2"

int main(int argc, char** argv)
{
	Logger::EnableANSIColors();

	CLI::App app{ "Roblox Static Page Decryptor. Author: nasec", "Brochacha20" };

	std::string outputDir;
	std::string targetDir;
	bool silentMode = false;

	app.add_option("target", targetDir, "Roblox Directory (Where RobloxPlayerBeta.exe and RobloxPlayerBeta.dll are stored)")->required()->check(CLI::ExistingDirectory);
	app.add_option("--output,-o", outputDir, "Output File. Example: C:\\RbxDumps\\ClientDump.bin Default: targetDir\\RobloxPlayerBeta.bin");
	app.add_flag("--silent,-s", silentMode, "Silent mode. (No logging)");

	CLI11_PARSE(app, argc, argv);

	Logger::disableLogging = silentMode;
	if (outputDir.empty()) outputDir = targetDir + "\\RobloxPlayerBeta.bin";

	Logger::Log("Brochacha20 %s - nasec", BROCHACHA_VERSION);
	Logger::Log("Decrypted Client will be saved to %s",outputDir.c_str());
	Logger::Log("Decryption started..");

	PEFile* decryptedClient = DecryptRBXClient(targetDir);
	if (decryptedClient)
	{
		Logger::Success("Successfully decrypted Roblox Client!");
		Logger::Success("Writing to disk..");

		try
		{
			decryptedClient->Dump(outputDir);
			Logger::Success("Decrypted Client saved to \"%s\"", outputDir.c_str());
			Logger::Success("Thanks for using! :3");
		}
		catch (const std::exception& ex)
		{
			Logger::Error("Failed to write decrypted Client to Disk: %s",ex.what());
		}
	}
	else
	{
		Logger::Error("Failed to decrypt Roblox Client. Please report it ^^ discord: mrnasec");
	}

	return 0;
}

/*
int main(int argc, char** argv)
{
	//DecryptPage(0x2108F40 & 0xFFFFFFFFFFFFF000uLL);
	//DecryptAllPages();
	//HMODULE mod = LoadLibraryExW(L"RobloxPlayerBeta.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);
	//TestDecrypt();
	//PEDumper::Dump(mod);
}
*/


// * brochacho20... chacha20... brochacho??? bro"CHACHA"?? bro.. *
// https://cdn.discordapp.com/attachments/1397679298269413457/1398731310130008194/attachment.gif?ex=6887164b&is=6885c4cb&hm=8e33de33a549434f567a14e417209aa941873bdc2ee215bca04b915afa43eccd&
// https://cdn.discordapp.com/attachments/934170003773747220/1296975750582374461/attachment.gif?ex=6886b3cb&is=6885624b&hm=e0cf95e440064bb4add9785410cc280daf1c4a11ffccd7f2eebbd156d2653d87&
// https://cdn.discordapp.com/attachments/1175701901694734346/1227398921999876096/watermark.gif?ex=6886b552&is=688563d2&hm=1a28f936aa810b001d7820111a2007d1b101895f56542048d3b3f8f562b8f2ff&
// https://cdn.discordapp.com/attachments/1393319178383134772/1398982840196141207/attachment.gif?ex=688757cc&is=6886064c&hm=4cb2dd72f00e4420869438239276baa4b4389933c824a37301cf4bbbbbf8b2e1&