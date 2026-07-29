#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>

#include <string>
#include <fstream>
#include <vector>

struct MANUAL_MAP_MAIN
{
	HINSTANCE HinstDLL;
	DWORD FdwReason;
	LPVOID lpvReserved;
};

bool GetStructFile(std::wstring& wstr, std::vector<uint8_t>& FileStruct);
bool ChangeValidAddress(uintptr_t AllocBase, uintptr_t PreferedBase, uintptr_t LocalImage, IMAGE_DATA_DIRECTORY RelocData);
bool CreateLocalImage(std::vector<uint8_t>& LocalImage, std::vector<uint8_t>& ExternImage);
HMODULE SilentSearchDll(const char* Str);
bool ParseImports(IMAGE_DATA_DIRECTORY ImportData, uintptr_t LocalImageData, DWORD pid, std::wstring& PathDll, std::string& output, std::wstring PathExe);

void __stdcall ShellCode(MANUAL_MAP_MAIN* pData);
void __stdcall ShellCodeEnd();