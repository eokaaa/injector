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
	uintptr_t RIP;
};

DWORD GetThreadID(DWORD PID);

bool SilentOpenProcess(DWORD hTargetModule, HANDLE* pOutTargetProcessHandle);
bool SilentOpenThread(DWORD hTargetModule, HANDLE* pOutTargetProcessHandle);
bool SilentCloseHandle(HANDLE hProcess);

LPVOID SilentAllocate(HANDLE hProcess, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T pSize, ULONG AllocationType);
bool SilentWriteProcess(HANDLE hProcess, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);
bool SilentFreeAllocate(HANDLE hProcess, PVOID* BaseAddress);
bool SilientProtectMemory(HANDLE hProcess, PVOID* BaseAddress, SIZE_T pSize, ULONG NewProtect, PULONG OldProtrect);

bool SilentSuspendThread(HANDLE hThread, PULONG PreviousSuspendCount = 0);
bool SilentResumeThread(HANDLE hThread, PULONG PreviousSuspendCount = 0);
bool SilentGetContextThread(HANDLE hThread, PCONTEXT ThreadContext);
bool SilentSetContextThread(HANDLE hThread, PCONTEXT ThreadContext);

HMODULE SilentSearchDll(const char* Str);

bool GetStructFile(std::wstring& wstr, std::vector<uint8_t>& FileStruct);

bool ChangeValidAddress(uintptr_t AllocBase, uintptr_t PreferedBase, uintptr_t LocalImage, IMAGE_DATA_DIRECTORY RelocData);

bool CreateLocalImage(std::vector<uint8_t>& LocalImage, std::vector<uint8_t>& ExternImage);

bool ParseImports(IMAGE_DATA_DIRECTORY ImportData, uintptr_t LocalImageData, DWORD pid, std::wstring& PathDll, std::string& output, std::wstring PathExe);

void __stdcall ShellCode(MANUAL_MAP_MAIN* pData);
void __stdcall ShellCodeEnd();