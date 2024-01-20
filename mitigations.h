#pragma once
#include <string>
#include "win.h"

std::wstring widen(std::string utf8String) {
	std::wstring out;

	size_t size_needed = MultiByteToWideChar(CP_UTF8, 0, utf8String.c_str(), (int) utf8String.length(), nullptr, 0);
	out.resize(size_needed);
	MultiByteToWideChar(CP_UTF8, 0, utf8String.c_str(), (int) utf8String.length(), (wchar_t*)out.c_str(), (int)size_needed);

	return out;
};
std::string narrow(std::wstring utf16String) {
	std::string out;

	size_t size_needed = WideCharToMultiByte(CP_UTF8, 0, utf16String.c_str(), (int) utf16String.length(), nullptr, 0, nullptr, nullptr);
	out.resize(size_needed);
	WideCharToMultiByte(CP_UTF8, 0, utf16String.c_str(), (int) utf16String.length(), (char*)out.c_str(), (int)size_needed, nullptr, nullptr);

	return out;
};