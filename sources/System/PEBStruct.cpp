#include "PEBStruct.h"
#include "NtStruct.h"

#include "sources/Core/ParseModules.h"
#include "sources/Utils/Utils.h"

HMODULE SilentSearchDll(const char* Str)
{
	PPEB PEB = (PPEB)__readgsqword(0x60);

	PFULL_PEB_LDR_DATA  PpebLdr = (PFULL_PEB_LDR_DATA)PEB->Ldr;

	PLIST_ENTRY ListHead = &PpebLdr->InLoadOrderModuleList;
	PLIST_ENTRY CurrentEntry = ListHead->Flink;

	std::wstring SearchString = utf8ToWstring(std::string(Str));

	while (CurrentEntry != ListHead)
	{
		PFULL_LDR_DATA_TABLE_ENTRY pModule = (PFULL_LDR_DATA_TABLE_ENTRY)CurrentEntry;

		if (pModule->BaseDllName.Buffer != 0)
		{
			size_t ModLen = pModule->BaseDllName.Length / sizeof(wchar_t);
			size_t SearchStrSize = SearchString.size();

			if (ModLen == SearchStrSize && _wcsnicmp(pModule->BaseDllName.Buffer, SearchString.c_str(), SearchStrSize) == 0)
				return (HMODULE)pModule->DllBase;
		}

		CurrentEntry = CurrentEntry->Flink;
	}

	if (_strnicmp(Str, "api-ms-win-crt-", 15) == 0)
	{
		HMODULE hUcrt = SilentSearchDll("ucrtbase.dll");
		if (hUcrt) return hUcrt;

		auto it = MappedModules.find("ucrtbase.dll");
		if (it != MappedModules.end())
			return (HMODULE)it->second;
	}

	if (_strnicmp(Str, "api-ms-", 7) == 0 || _strnicmp(Str, "ext-ms-", 7) == 0)
	{
		HMODULE hKernelBase = SilentSearchDll("kernelbase.dll");
		if (hKernelBase)
			return hKernelBase;

		return SilentSearchDll("kernel32.dll");
	}

	return 0;
}

std::wstring GetSystemPath()
{
	PPEB PEB = (PPEB)__readgsqword(0x60);
	MY_PRTL_USER_PROCESS_PARAMETERS PebProcess = (MY_PRTL_USER_PROCESS_PARAMETERS)PEB->ProcessParameters;

	wchar_t* env = (wchar_t*)PebProcess->Environment;
	while (*env)
	{
		if (_wcsnicmp(env, L"SystemRoot=", 11) == 0)
			return std::wstring(env + 11);

		env += wcslen(env) + 1;
	}

	return L"C:\\Windows";
}

std::wstring GetEnvFromPEB(const wchar_t* Str)
{
	PPEB PEB = (PPEB)__readgsqword(0x60);
	MY_PRTL_USER_PROCESS_PARAMETERS PebProcess = (MY_PRTL_USER_PROCESS_PARAMETERS)PEB->ProcessParameters;

	wchar_t* env = (wchar_t*)PebProcess->Environment;
	size_t VarvLen = wcslen(Str);

	while (*env)
	{
		if (_wcsnicmp(env, Str, VarvLen) == 0)
			return std::wstring(env + VarvLen);

		env += wcslen(env) + 1;
	}

	return L"C:\\Windows";
}
