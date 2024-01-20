#pragma once
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>

extern "C" {
	bool fReadProcessMemory(
		HANDLE  hProcess,
		void* lpBaseAddress,
		void* lpBuffer,
		size_t  nSize,
		size_t* lpNumberOfBytesRead
	);
};