#pragma once
#include <windows.h>
#include <string>

bool LoadLibraryDllInject(DWORD pid, std::wstring& directoryPath, std::string& output);