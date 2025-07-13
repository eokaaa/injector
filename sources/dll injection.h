#pragma once
#include <windows.h>
#include <string>

bool dllInject(DWORD pid, std::wstring& directoryPath, std::string& output);