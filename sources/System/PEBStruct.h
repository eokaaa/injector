#pragma once

#include <windows.h>
#include <string>

HMODULE SilentSearchDll(const char* Str);
std::wstring GetSystemPath();
std::wstring GetEnvFromPEB(const wchar_t* Str);