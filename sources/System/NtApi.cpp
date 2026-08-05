#include "NtStruct.h"
#include "NtApi.h"
#include "PEBStruct.h"

#include "sources/Core/ParseModules.h"

DWORD GetThreadID(DWORD PID)
{
	DWORD ThreadID = 0;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		THREADENTRY32 te = { sizeof(te) };
		if (Thread32First(hSnapshot, &te))
		{
			do
			{
				if (te.th32OwnerProcessID == PID)
				{
					ThreadID = te.th32ThreadID;
					break;
				}
			} while (Thread32Next(hSnapshot, &te));
		}
		SilentCloseHandle(hSnapshot);
	}

	return ThreadID;
}


uintptr_t GetProcAddressByName(HMODULE hModule, const char* lpProcName, const std::wstring& PathExe = L"");
std::wstring UniversalFileExists(const char* DllName, const std::wstring& GameFolder);

bool SilentOpenProcess(DWORD hTargetModule, HANDLE* pOutTargetProcessHandle)
{
	if (!hTargetModule)
		return false;

	HMODULE hModule = SilentSearchDll("ntdll.dll");
	if (!hModule)
		return false;

	pfnNtOpenProcess NtOpenProcess = (pfnNtOpenProcess)GetProcAddressByName(hModule, "NtOpenProcess");
	if (!NtOpenProcess)
		return false;

	OBJECT_ATTRIBUTES obj;
	ZeroMemory(&obj, sizeof(OBJECT_ATTRIBUTES));
	obj.Length = sizeof(OBJECT_ATTRIBUTES);

	MY_CLIENT_ID ClientId;
	ClientId.UniqueProcess = (HANDLE)(uintptr_t)hTargetModule;
	ClientId.UniqueThread = NULL;

	auto Mask = PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_LIMITED_INFORMATION;
	HANDLE hProcess = NULL;

	NTSTATUS Status = NtOpenProcess(&hProcess, Mask, &obj, &ClientId);

	if (Status >= 0)
	{
		*pOutTargetProcessHandle = hProcess;
		return true;
	}

	return false;
}

bool SilentOpenThread(DWORD hTargetModule, HANDLE* pOutTargetProcessHandle)
{
	if (!hTargetModule)
		return false;

	HMODULE hNtModule = SilentSearchDll("ntdll.dll");
	if (!hNtModule)
		return false;

	pfnNtOpenThread NtOpenThread = (pfnNtOpenThread)GetProcAddressByName(hNtModule, "NtOpenThread");
	if (!NtOpenThread)
		return false;

	OBJECT_ATTRIBUTES obj;
	ZeroMemory(&obj, sizeof(OBJECT_ATTRIBUTES));
	obj.Length = sizeof(OBJECT_ATTRIBUTES);

	MY_CLIENT_ID ClientId;
	ClientId.UniqueProcess = NULL;
	ClientId.UniqueThread = (HANDLE)(uintptr_t)hTargetModule;

	auto Mask = THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | SYNCHRONIZE;
	HANDLE hThread = NULL;

	NTSTATUS Status = NtOpenThread(&hThread, Mask, &obj, &ClientId);

	if (Status >= 0)
	{
		*pOutTargetProcessHandle = hThread;
		return true;
	}

	return false;
}

bool SilentCloseHandle(HANDLE hProcess)
{
	if (!hProcess)
		return false;

	HMODULE hNtModule = SilentSearchDll("ntdll.dll");
	if (!hNtModule)
		return false;

	pfnNtClose NtClose = (pfnNtClose)GetProcAddressByName(hNtModule, "NtClose");
	if (!NtClose)
		return false;

	NTSTATUS Status = NtClose(hProcess);

	return (Status >= 0);
}

LPVOID SilentAllocate(HANDLE hProcess, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T pSize, ULONG AllocationType)
{
	if (!hProcess || !pSize ||
		!*pSize || !AllocationType)
		return 0;

	HMODULE hNtModule = SilentSearchDll("ntdll.dll");
	if (!hNtModule)
		return 0;

	pfnNtAllocateVirtualMemory NtAllocateVirtualMemory = (pfnNtAllocateVirtualMemory)GetProcAddressByName(hNtModule, "NtAllocateVirtualMemory");
	if (!NtAllocateVirtualMemory)
		return 0;

	NTSTATUS Status = NtAllocateVirtualMemory(hProcess, BaseAddress, ZeroBits, pSize, AllocationType, PAGE_READWRITE);

	if (Status < 0)
		return 0;

	return *BaseAddress;
}


bool SilentReadProcess(HANDLE hProcess, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead)
{
	if (!hProcess || !BaseAddress ||
		!Buffer || !NumberOfBytesToRead)
		return false;

	HMODULE hNtModule = SilentSearchDll("ntdll.dll");
	if (!hNtModule)
		return false;

	pfnNtReadVirtualMemory NtReadVirtualMemory = (pfnNtReadVirtualMemory)GetProcAddressByName(hNtModule, "NtReadVirtualMemory");
	if (!NtReadVirtualMemory)
		return false;

	NTSTATUS Status = NtReadVirtualMemory(hProcess, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);

	return (Status >= 0);
}

bool SilentWriteProcess(HANDLE hProcess, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten)
{
	if (!hProcess || !BaseAddress ||
		!Buffer || !NumberOfBytesToWrite)
		return false;

	HMODULE hNtModule = SilentSearchDll("ntdll.dll");
	if (!hNtModule)
		return false;

	pfnNtWriteVirtualMemory NtWriteVirtualMemory = (pfnNtWriteVirtualMemory)GetProcAddressByName(hNtModule, "NtWriteVirtualMemory");
	if (!NtWriteVirtualMemory)
		return false;

	NTSTATUS Status = NtWriteVirtualMemory(hProcess, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);

	return (Status >= 0);
}

bool SilentFreeAllocate(HANDLE hProcess, PVOID* BaseAddress)
{
	if (!hProcess || !BaseAddress || !*BaseAddress)
		return false;

	HMODULE hNtModule = SilentSearchDll("ntdll.dll");
	if (!hNtModule)
		return false;

	qfnNtFreeVirtualMemory NtFreeVirtualMemory = (qfnNtFreeVirtualMemory)GetProcAddressByName(hNtModule, "NtFreeVirtualMemory");
	if (!NtFreeVirtualMemory)
		return false;

	SIZE_T pSize = 0;

	NTSTATUS Status = NtFreeVirtualMemory(hProcess, BaseAddress, &pSize, MEM_RELEASE);

	return (Status >= 0);
}

bool SilentProtectMemory(HANDLE hProcess, PVOID* BaseAddress, SIZE_T pSize, ULONG NewProtect, PULONG OldProtrect)
{
	if (!hProcess || !BaseAddress || !pSize)
		return false;

	ULONG DummyProtect = 0;
	PULONG pOldProtect = OldProtrect ? OldProtrect : &DummyProtect;

	HMODULE hNtModule = SilentSearchDll("ntdll.dll");
	if (!hNtModule)
		return false;

	pfnNtProtectVirtualMemory NtProtectVirtualMemory = (pfnNtProtectVirtualMemory)GetProcAddressByName(hNtModule, "NtProtectVirtualMemory");
	if (!NtProtectVirtualMemory)
		return false;

	PVOID CopyBaseAddress = *BaseAddress;
	SIZE_T CopySize = pSize;

	NTSTATUS Status = NtProtectVirtualMemory(hProcess, &CopyBaseAddress, &CopySize, NewProtect, pOldProtect);

	return (Status >= 0);
}


bool SilentSuspendThread(HANDLE hThread, PULONG PreviousSuspendCount)
{
	if (!hThread)
		return false;

	HMODULE hNtModule = SilentSearchDll("ntdll.dll");
	if (!hNtModule)
		return false;

	pfnNtSuspendThread NtSuspendThread = (pfnNtSuspendThread)GetProcAddressByName(hNtModule, "NtSuspendThread");
	if (!NtSuspendThread)
		return false;

	NTSTATUS Status = NtSuspendThread(hThread, PreviousSuspendCount);

	return (Status >= 0);
}

bool SilentResumeThread(HANDLE hThread, PULONG PreviousSuspendCount)
{
	if (!hThread)
		return false;

	HMODULE hNtModule = SilentSearchDll("ntdll.dll");
	if (!hNtModule)
		return false;

	pfnNtResumeThread NtResumeThread = (pfnNtResumeThread)GetProcAddressByName(hNtModule, "NtResumeThread");
	if (!NtResumeThread)
		return false;

	NTSTATUS Status = NtResumeThread(hThread, PreviousSuspendCount);

	return (Status >= 0);
}

bool SilentGetContextThread(HANDLE hThread, PCONTEXT ThreadContext)
{
	if (!hThread || !ThreadContext)
		return false;

	HMODULE hNtModule = SilentSearchDll("ntdll.dll");
	if (!hNtModule)
		return false;

	pfnNtGetContextThread NtGetContextThread = (pfnNtGetContextThread)GetProcAddressByName(hNtModule, "NtGetContextThread");
	if (!NtGetContextThread)
		return false;

	NTSTATUS Status = NtGetContextThread(hThread, ThreadContext);

	return (Status >= 0);
}

bool SilentSetContextThread(HANDLE hThread, PCONTEXT ThreadContext)
{
	if (!hThread || !ThreadContext)
		return false;

	HMODULE hNtModule = SilentSearchDll("ntdll.dll");
	if (!hNtModule)
		return false;

	pfnNtSetContextThread NtSetContextThread = (pfnNtSetContextThread)GetProcAddressByName(hNtModule, "NtSetContextThread");
	if (!NtSetContextThread)
		return false;

	NTSTATUS Status = NtSetContextThread(hThread, ThreadContext);

	return (Status >= 0);
}

bool FileExists(std::wstring& FullPath, const std::wstring& PathExe)
{
	HMODULE hModule = SilentSearchDll("ntdll.dll");
	if (!hModule)
		return false;

	pfnNtQueryAttributesFile NtQueryAttributeFile = (pfnNtQueryAttributesFile)GetProcAddressByName(hModule, "NtQueryAttributesFile", PathExe);
	if (!NtQueryAttributeFile)
		return false;

	std::wstring NtPath = L"\\??\\" + FullPath;

	UNICODE_STRING uStr;
	RtlInitUnicodeString(&uStr, NtPath.c_str());

	OBJECT_ATTRIBUTES ObjAttribute;
	InitializeObjectAttributes(&ObjAttribute, &uStr, OBJ_CASE_INSENSITIVE, NULL, NULL);

	FILE_BASIC_INFORMATION FileInfo;
	NTSTATUS Status = NtQueryAttributeFile(&ObjAttribute, &FileInfo);

	return (Status >= 0);
}