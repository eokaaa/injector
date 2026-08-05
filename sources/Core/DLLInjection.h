#pragma once
#include <windows.h>
#include <string>

bool LoadLibraryDllInject(DWORD pid, std::wstring& directoryPath, std::string& output);
uintptr_t ManualMapDllInject(DWORD pid, std::wstring PathDll, std::string& output, std::wstring PathExe = L"");