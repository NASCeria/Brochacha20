#include <iostream>
#include <string>
#include <cstdarg>
#include <windows.h>

namespace Logger
{
	static bool disableLogging = false;

	// AI
	void EnableANSIColors() 
	{
		HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
		if (hOut == INVALID_HANDLE_VALUE) return;

		DWORD dwMode = 0;
		if (!GetConsoleMode(hOut, &dwMode)) return;

		dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING; // Enable ANSI
		SetConsoleMode(hOut, dwMode);
	}

    // AI
    void PrintTimestamp() {
        time_t now = time(nullptr);
        tm* local = localtime(&now);

        printf("\033[90m%02d:%02d:%02d\033[0m ", local->tm_hour, local->tm_min, local->tm_sec);
    }

    void Log(const char* fmt, ...) {
        if (disableLogging) return;

        PrintTimestamp();
        printf("\033[36m[INFO]\033[0m ");

        va_list args;
        va_start(args, fmt);
        vprintf(fmt, args);
        va_end(args);

        printf("\n");
    }

    void Error(const char* fmt, ...) {
        if (disableLogging) return;

        PrintTimestamp();
        printf("\033[91m[ERROR]\033[0m ");

        va_list args;
        va_start(args, fmt);
        vprintf(fmt, args);
        va_end(args);

        printf("\n");
    }

    void Success(const char* fmt, ...) {
        if (disableLogging) return;

        PrintTimestamp();
        printf("\033[92m[SUCCESS]\033[0m ");

        va_list args;
        va_start(args, fmt);
        vprintf(fmt, args);
        va_end(args);

        printf("\n");
    }

    void Debug(const char* fmt, ...) {
        if (disableLogging) return;

        PrintTimestamp();
        printf("\033[35m[DEBUG]\033[0m ");

        va_list args;
        va_start(args, fmt);
        vprintf(fmt, args);
        va_end(args);

        printf("\n");
    }

}