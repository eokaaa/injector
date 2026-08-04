#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>

#include <string>
#include <fstream>
#include <vector>
#include <unordered_map>

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

DWORD GetThreadID(DWORD PID);

bool SilentOpenProcess(DWORD hTargetModule, HANDLE* pOutTargetProcessHandle);
bool SilentOpenThread(DWORD hTargetModule, HANDLE* pOutTargetProcessHandle);
bool SilentCloseHandle(HANDLE hProcess);

LPVOID SilentAllocate(HANDLE hProcess, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T pSize, ULONG AllocationType);
bool SilentReadProcess(HANDLE hProcess, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead);
bool SilentWriteProcess(HANDLE hProcess, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);
bool SilentFreeAllocate(HANDLE hProcess, PVOID* BaseAddress);
bool SilientProtectMemory(HANDLE hProcess, PVOID* BaseAddress, SIZE_T pSize, ULONG NewProtect, PULONG OldProtrect);

bool SilentSuspendThread(HANDLE hThread, PULONG PreviousSuspendCount = 0);
bool SilentResumeThread(HANDLE hThread, PULONG PreviousSuspendCount = 0);
bool SilentGetContextThread(HANDLE hThread, PCONTEXT ThreadContext);
bool SilentSetContextThread(HANDLE hThread, PCONTEXT ThreadContext);

HMODULE SilentSearchDll(const char* Str);

uintptr_t GetProcAddressByName(HMODULE hModule, const char* lpProcName, const std::wstring& PathExe);

bool GetStructFile(std::wstring& wstr, std::vector<uint8_t>& FileStruct);

bool ParseReloc(uintptr_t AllocBase, uintptr_t PreferedBase, uintptr_t LocalImage, IMAGE_DATA_DIRECTORY RelocData);

bool CreateLocalImage(std::vector<uint8_t>& LocalImage, std::vector<uint8_t>& ExternImage);

bool ParseImports(IMAGE_DATA_DIRECTORY ImportData, uintptr_t LocalImageData, DWORD DllSizeOfImage, HANDLE hProcess, std::wstring& PathDll, std::string& output, std::wstring PathExe);