#pragma once

#include <string>
#include <windows.h>

DWORD GetThreadID(DWORD PID);

bool SilentOpenProcess(DWORD hTargetModule, HANDLE* pOutTargetProcessHandle);
bool SilentOpenThread(DWORD hTargetModule, HANDLE* pOutTargetProcessHandle);
bool SilentCloseHandle(HANDLE hProcess);

LPVOID SilentAllocate(HANDLE hProcess, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T pSize, ULONG AllocationType);
bool SilentReadProcess(HANDLE hProcess, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead);
bool SilentWriteProcess(HANDLE hProcess, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);
bool SilentFreeAllocate(HANDLE hProcess, PVOID* BaseAddress);
bool SilentProtectMemory(HANDLE hProcess, PVOID* BaseAddress, SIZE_T pSize, ULONG NewProtect, PULONG OldProtrect);

bool SilentSuspendThread(HANDLE hThread, PULONG PreviousSuspendCount = 0);
bool SilentResumeThread(HANDLE hThread, PULONG PreviousSuspendCount = 0);
bool SilentGetContextThread(HANDLE hThread, PCONTEXT ThreadContext);
bool SilentSetContextThread(HANDLE hThread, PCONTEXT ThreadContext);

bool FileExists(std::wstring& FullPath, const std::wstring& PathExe);