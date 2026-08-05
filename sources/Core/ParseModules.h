#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>

#include <string>
#include <fstream>
#include <vector>
#include <unordered_map>

#include "sources/System/NtApi.h"
#include "sources/System/PEBStruct.h"

inline std::unordered_map<std::string, uintptr_t> MappedModules;
inline std::unordered_map<std::string, std::vector<uint8_t>> LocalImagesCache;

struct MANUAL_MAP_MAIN
{
	HINSTANCE		HinstDLL;
	DWORD			FdwReason;
	DWORD			pad1;
	LPVOID			lpvReserved;
	DWORD			EntryPoint;
	DWORD			pad2;
	volatile DWORD	Done;
	PVOID			FunctionTable;
	DWORD			EntryCount;
	DWORD			pad4;
	PVOID			BaseAddress;
	PVOID			RtlAddFunctionTable;
	ULONG_PTR		TLSCallbacks;
};


uintptr_t GetProcAddressByName(HMODULE hModule, const char* lpProcName, const std::wstring& PathExe);
bool ParseReloc(uintptr_t AllocBase, uintptr_t PreferedBase, uintptr_t LocalImage, IMAGE_DATA_DIRECTORY RelocData);
bool ParseImports(IMAGE_DATA_DIRECTORY ImportData, uintptr_t LocalImageData, DWORD DllSizeOfImage, HANDLE hProcess, std::wstring& PathDll, std::string& output, std::wstring PathExe);