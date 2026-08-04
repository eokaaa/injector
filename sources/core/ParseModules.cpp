#include "ParseModules.h"
#include "dll injection.h"
#include "NtStruct.h"

#include "../search/searchDll.h"

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
	ClientId.UniqueThread  = NULL;

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
	ClientId.UniqueThread  = (HANDLE)(uintptr_t)hTargetModule;

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
		!*pSize   || !AllocationType)
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

bool SilientProtectMemory(HANDLE hProcess, PVOID* BaseAddress, SIZE_T pSize, ULONG NewProtect, PULONG OldProtrect)
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


bool GetStructFile(std::wstring& wstr, std::vector<uint8_t>& FileStruct)
{
	std::ifstream OpenFile(wstr, std::ios::binary);
	if (OpenFile.is_open())
	{
		OpenFile.seekg(0, OpenFile.end);
		uint32_t Length = OpenFile.tellg();
		OpenFile.seekg(0, OpenFile.beg);

		FileStruct.resize(Length);
		if (OpenFile.read((char*)FileStruct.data(), Length))
			return true;
	}

	return false;
}

bool ParseReloc(uintptr_t AllocBase, uintptr_t PreferedBase, uintptr_t LocalImage, IMAGE_DATA_DIRECTORY RelocData)
{
	if (AllocBase == 0 || PreferedBase == 0 || RelocData.VirtualAddress == 0)
		return false;

	uintptr_t delta = AllocBase - PreferedBase;
	if (delta == 0)
		return true;

	uintptr_t StartReloc = LocalImage + RelocData.VirtualAddress;
	uintptr_t EndReloc = StartReloc + RelocData.Size;

	PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)StartReloc;

	while ((uintptr_t)reloc < EndReloc && EndReloc > 0)
	{
		if (reloc->SizeOfBlock <= sizeof(IMAGE_BASE_RELOCATION) || 
			((uintptr_t)reloc + reloc->SizeOfBlock) > EndReloc)
			break;

		size_t EntryByte = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);

		uint16_t* ArrayByte = (uint16_t*)((uintptr_t)reloc + sizeof(IMAGE_BASE_RELOCATION));

		for (int i = 0; i < EntryByte; ++i)
		{
			uint16_t Entry = ArrayByte[i];

			uint16_t High = Entry >> 12;
			uint16_t Low = Entry & 0x0FFF;

			if (High == IMAGE_REL_BASED_ABSOLUTE)
				continue;

			uintptr_t AbsoluteAddress = LocalImage + reloc->VirtualAddress + Low;

			if (High == IMAGE_REL_BASED_DIR64)
				*(uint64_t*)AbsoluteAddress += delta;
			else if (High == IMAGE_REL_BASED_HIGHLOW)
				*(uint32_t*)AbsoluteAddress += (uint32_t)delta;
		}

		reloc = (PIMAGE_BASE_RELOCATION)((uint8_t*)reloc + reloc->SizeOfBlock);;
	}


	return true;
}

bool CreateLocalImage(std::vector<uint8_t>& LocalImage, std::vector<uint8_t>& ExternImage)
{
	IMAGE_DOS_HEADER* ExternIDos = (IMAGE_DOS_HEADER*)(ExternImage.data());
	IMAGE_NT_HEADERS* ExternINT = (IMAGE_NT_HEADERS*)(ExternImage.data() + ExternIDos->e_lfanew);
	if (ExternIDos->e_magic != IMAGE_DOS_SIGNATURE ||
		ExternINT->Signature != IMAGE_NT_SIGNATURE)
		return false;

	DWORD SizeOfImage = 0;
	DWORD SizeOfHeaders = 0;
	if (ExternINT->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		auto ExternINT64 = (IMAGE_NT_HEADERS64*)ExternINT;
		SizeOfImage = ExternINT64->OptionalHeader.SizeOfImage;
		SizeOfHeaders = ExternINT64->OptionalHeader.SizeOfHeaders;
	}
	else
	{
		auto ExternINT32 = (IMAGE_NT_HEADERS32*)ExternINT;
		SizeOfImage = ExternINT32->OptionalHeader.SizeOfImage;
		SizeOfHeaders = ExternINT32->OptionalHeader.SizeOfHeaders;
	}

	LocalImage.resize(SizeOfImage, 0);
	std::memcpy(LocalImage.data(), ExternImage.data(), SizeOfHeaders);

	IMAGE_SECTION_HEADER* DepSections = IMAGE_FIRST_SECTION(ExternINT);
	for (int i = 0; i < ExternINT->FileHeader.NumberOfSections; ++i, ++DepSections)
	{
		if (DepSections->SizeOfRawData > 0 && DepSections->PointerToRawData > 0)
		{
			std::memcpy(
				LocalImage.data() + DepSections->VirtualAddress,
				ExternImage.data() + DepSections->PointerToRawData,
				DepSections->SizeOfRawData
			);
		}
	}

	return true;
}

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


uintptr_t GetProcAddressByOrdinal(HMODULE DllModule, uintptr_t TargetOrdinal)
{
	PBYTE pBase = (PBYTE)DllModule;
	if (pBase == 0)
		return 0;

	PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)pBase;
	if (pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return 0;

	PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)(pBase + pDOSHeader->e_lfanew);
	if (pNTHeaders->Signature != IMAGE_NT_SIGNATURE)
		return 0;

	IMAGE_DATA_DIRECTORY pDataExport = pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (pDataExport.VirtualAddress == 0)
		return 0;

	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(pBase + pDataExport.VirtualAddress);

	if (TargetOrdinal < pExport->Base || TargetOrdinal >= (pExport->Base + pExport->NumberOfFunctions))
		return 0;

	DWORD idx = TargetOrdinal - pExport->Base;

	DWORD* AddressOfFunc = (DWORD*)(pBase + pExport->AddressOfFunctions);
	DWORD  FuncRVA = AddressOfFunc[idx];

	if (FuncRVA == 0)
		return 0;

	if (FuncRVA >= pDataExport.VirtualAddress &&
		FuncRVA < pDataExport.VirtualAddress + pDataExport.Size)
		return 0;

	return (uintptr_t)(FuncRVA);
}


uintptr_t GetProcRVAByName(HMODULE DllModule, const char* lpProcName, const std::wstring& PathExe)
{
	PBYTE pBase = (PBYTE)DllModule;
	if (pBase == 0)
		return 0;

	PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)pBase;
	if (pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return 0;

	PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)(pBase + pDOSHeader->e_lfanew);
	if (pNTHeaders->Signature != IMAGE_NT_SIGNATURE)
		return 0;

	IMAGE_DATA_DIRECTORY pDataExport = pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (pDataExport.VirtualAddress == 0)
		return 0;

	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(pBase + pDataExport.VirtualAddress);

	DWORD* AddressOfFunctions	 = (DWORD*)(pBase + pExport->AddressOfFunctions);
	DWORD* AddressOfNames		 = (DWORD*)(pBase + pExport->AddressOfNames);
	WORD*  AddressOfNameOrdinals = (WORD*)(pBase + pExport->AddressOfNameOrdinals);

	std::vector<uint8_t> LocalFwdRaw;
	for (int i = 0; i < pExport->NumberOfNames; ++i)
	{
		if (strcmp(lpProcName, (const char*)(pBase + AddressOfNames[i])) != 0)
			continue;
		
		WORD Ordinal = AddressOfNameOrdinals[i];

		DWORD FunctionRVA = AddressOfFunctions[Ordinal];

		if (FunctionRVA >= pDataExport.VirtualAddress &&
			FunctionRVA < pDataExport.VirtualAddress + pDataExport.Size)
		{
			std::string Fwd = (const char*)(pBase + FunctionRVA);
			size_t DotPos = Fwd.find('.');

			if (DotPos == std::string::npos)
				return 0;

			std::string TargetName = Fwd.substr(0, DotPos) + ".dll";
			std::string FuncName   = Fwd.substr(DotPos + 1);

			HMODULE TargetDll = SilentSearchDll(TargetName.c_str());
			if (!TargetDll)
				return 0;
			
			uintptr_t AbsAddr = GetProcAddressByName(TargetDll, FuncName.c_str(), PathExe);
			if (!AbsAddr)
				return 0;
			return (DWORD)(AbsAddr - (uintptr_t)DllModule);
		}

		return (uintptr_t)(FunctionRVA);
	}

	return 0;
}

uintptr_t GetProcAddressByName(HMODULE hModule, const char* lpProcName, const std::wstring& PathExe)
{
	DWORD rva = GetProcRVAByName(hModule, lpProcName, PathExe);
	if (!rva)
		return 0;

	return (uintptr_t)hModule + rva;
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

std::wstring UniversalFileExists(const char* DllName, const std::wstring& GameFolder)
{
	std::wstring DllNameWSTR = utf8ToWstring(std::string(DllName));

	if (!GameFolder.empty())
	{
		std::wstring FullDir = GameFolder + L"\\" + DllNameWSTR;
		if (FileExists(FullDir, GameFolder))
			return FullDir;
	}

	std::wstring System32 = GetSystemPath() + L"\\System32\\" + DllNameWSTR;
	if (FileExists(System32, GameFolder))
		return System32;

	std::wstring WinDir = GetSystemPath() + L"\\" + DllNameWSTR;
	if (FileExists(WinDir, GameFolder))
		return WinDir;

	std::wstring EnvPath = GetEnvFromPEB(L"Path=");
	if (!EnvPath.empty())
	{
		size_t Start = 0;
		size_t End = EnvPath.find(L';');

		while (End != std::wstring::npos)
		{
			std::wstring Dir = EnvPath.substr(Start, End - Start);
			if (!Dir.empty())
			{
				std::wstring FullPath = Dir + L"\\" + DllNameWSTR;
				if (FileExists(FullPath, GameFolder))
					return FullPath;
			}

			Start = End + 1;
			End = EnvPath.find(L';', Start);
		}

		if (Start < EnvPath.size())
		{
			std::wstring Dir = EnvPath.substr(Start);
			std::wstring FullDir = Dir + L"\\" + DllNameWSTR;
			if (FileExists(FullDir, GameFolder))
				return FullDir;
		}
	}

	return L"";
}

uintptr_t MapModules(HANDLE hProcess, std::vector<uint8_t>& DepFileStruct, std::wstring PathExe,std::wstring PathDll, std::string& NameDll, std::string& output)
{
	std::vector<uint8_t> ExeFileStruct;
	if (!GetStructFile(PathExe, ExeFileStruct))
		return false;

	IMAGE_DOS_HEADER* ExeImageDOS = reinterpret_cast<IMAGE_DOS_HEADER*>(ExeFileStruct.data());
	IMAGE_NT_HEADERS* ExeImageNT = reinterpret_cast<IMAGE_NT_HEADERS*>(ExeFileStruct.data() + ExeImageDOS->e_lfanew);

	IMAGE_DOS_HEADER* DllImageDOS = reinterpret_cast<IMAGE_DOS_HEADER*>(DepFileStruct.data());
	IMAGE_NT_HEADERS* DllImageNT = reinterpret_cast<IMAGE_NT_HEADERS*>(DepFileStruct.data() + DllImageDOS->e_lfanew);


	uintptr_t DllImageBase = 0;
	size_t  DllSizeOfImage = 0;
	size_t  DllSizeOfHeaders = 0;

	IMAGE_DATA_DIRECTORY RelocData;
	IMAGE_DATA_DIRECTORY ImportData;

	bool DllIs64 = (DllImageNT->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

	if (DllIs64)
	{
		auto DllImageNT64 = (IMAGE_NT_HEADERS64*)DllImageNT;
		DllImageBase = DllImageNT64->OptionalHeader.ImageBase;
		DllSizeOfImage = DllImageNT64->OptionalHeader.SizeOfImage;
		DllSizeOfHeaders = DllImageNT64->OptionalHeader.SizeOfHeaders;

		RelocData = DllImageNT64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		ImportData = DllImageNT64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	}
	else
	{
		auto DllImageNT32 = (IMAGE_NT_HEADERS32*)DllImageNT;
		DllImageBase = DllImageNT32->OptionalHeader.ImageBase;
		DllSizeOfImage = DllImageNT32->OptionalHeader.SizeOfImage;
		DllSizeOfHeaders = DllImageNT32->OptionalHeader.SizeOfHeaders;

		RelocData = DllImageNT32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		ImportData = DllImageNT32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	}


	PVOID pBaseAddress = NULL;

	LPVOID VirtualAllocateDll = SilentAllocate(hProcess, &pBaseAddress, 0, &DllSizeOfImage, MEM_COMMIT | MEM_RESERVE);
	if (!VirtualAllocateDll)
		return false;

	uintptr_t MemoryAllocate = reinterpret_cast<uintptr_t>(VirtualAllocateDll);
	MappedModules[NameDll] = MemoryAllocate;

	std::vector<uint8_t> LocalImage(DllSizeOfImage, 0);
	std::memcpy(LocalImage.data(), DepFileStruct.data(), DllSizeOfHeaders);

	IMAGE_SECTION_HEADER* Sections = IMAGE_FIRST_SECTION(DllImageNT);
	for (int i = 0; i < DllImageNT->FileHeader.NumberOfSections; ++i, ++Sections)
	{
		if (Sections->SizeOfRawData > 0 && Sections->PointerToRawData > 0)
		{
			std::memcpy(
				LocalImage.data() + Sections->VirtualAddress,
				DepFileStruct.data() + Sections->PointerToRawData,
				Sections->SizeOfRawData
			);
		}
	}

	uintptr_t LocalImageData = reinterpret_cast<uintptr_t>(LocalImage.data());

	if (!ParseReloc(MemoryAllocate, DllImageBase, LocalImageData, RelocData))
		return false;

	LocalImagesCache[NameDll] = std::move(LocalImage);

	if (!ParseImports(ImportData, LocalImageData, DllSizeOfImage, hProcess, PathDll, output, PathExe))
		return false;

	if (!SilentWriteProcess(hProcess, VirtualAllocateDll, LocalImagesCache[NameDll].data(), DllSizeOfImage, 0))
		return false;

	ULONG OldProtect = 0;
	SilientProtectMemory(hProcess, &VirtualAllocateDll, DllSizeOfImage, PAGE_EXECUTE_READWRITE, &OldProtect);

	return MemoryAllocate;
}

bool ParseImports(IMAGE_DATA_DIRECTORY ImportData, uintptr_t LocalImageData, DWORD DllSizeOfImage, HANDLE hProcess, std::wstring& PathDll, std::string& output, std::wstring PathExe)
{
	if (ImportData.VirtualAddress == 0 || LocalImageData == 0)
		return false;

	uintptr_t StartImport = LocalImageData + ImportData.VirtualAddress;
	uintptr_t EndImport = StartImport + ImportData.Size;

	PIMAGE_IMPORT_DESCRIPTOR IAT = (PIMAGE_IMPORT_DESCRIPTOR)StartImport;

	while (IAT->FirstThunk != 0 && IAT->Name != 0)
	{
		if ((uintptr_t)IAT >= EndImport)
			break;

		if (IAT->Name == 0 || IAT->Name >= DllSizeOfImage)
			break;

		uintptr_t NameAddress = LocalImageData + IAT->Name;

		const char* rawDllName = (const char*)NameAddress;

		std::string NameDll((const char*)(LocalImageData + IAT->Name));

		PIMAGE_THUNK_DATA ThunkData = (PIMAGE_THUNK_DATA)(LocalImageData + IAT->FirstThunk);

		uintptr_t OriginalThunkDataRVA = IAT->OriginalFirstThunk ? IAT->OriginalFirstThunk : IAT->FirstThunk;
		PIMAGE_THUNK_DATA OriginalThunkData = (PIMAGE_THUNK_DATA)(LocalImageData + OriginalThunkDataRVA);

		for (auto& ch : NameDll)
			ch = std::tolower(ch);

		HMODULE ModuleDll = SilentSearchDll(NameDll.c_str());
		uintptr_t RemoteModuleBase = 0;
		HMODULE LocalModule = nullptr;

		bool IsLoaded = false;

		if (ModuleDll != nullptr)
		{
			RemoteModuleBase = (uintptr_t)ModuleDll;
			LocalModule = ModuleDll;
			IsLoaded = true;
		}
		else if (MappedModules.contains(NameDll))
		{
			RemoteModuleBase = MappedModules[NameDll];
			LocalModule = (HMODULE)LocalImagesCache[NameDll].data();
			IsLoaded = false;
		}
		else if (!MappedModules.contains(NameDll) && !ModuleDll)
		{
			std::wstring DifferentPathDll = UniversalFileExists(NameDll.c_str(), PathExe);
			if (DifferentPathDll.empty())
				return false;

			std::vector<uint8_t> DepFileStruct;
			if (!GetStructFile(DifferentPathDll, DepFileStruct))
				return false;

			RemoteModuleBase = MapModules(hProcess, DepFileStruct, PathExe, PathDll, NameDll, output);
			if (!RemoteModuleBase)
				return false;

			LocalModule = (HMODULE)LocalImagesCache[NameDll].data();
			IsLoaded = false;
		}

		while (OriginalThunkData->u1.AddressOfData != 0)
		{
			uintptr_t FuncAddress = 0;

			if (IMAGE_SNAP_BY_ORDINAL(OriginalThunkData->u1.Ordinal))
			{
				WORD ordinal = IMAGE_ORDINAL(OriginalThunkData->u1.Ordinal);
				if (IsLoaded)
				{
					DWORD rva = GetProcAddressByOrdinal(LocalModule, ordinal);
					if (!rva)
					{

						output = "[!] Функция " + std::to_string(ordinal) + " была не найдена";
						return false;
					}
					FuncAddress = (uintptr_t)LocalModule + rva;
				}
				else
				{
					DWORD rva = GetProcAddressByOrdinal(LocalModule, ordinal);
					if (!rva)
					{

						output = "[!] Функция " + std::to_string(ordinal) + " была не найдена";
						return false;
					}
					FuncAddress = RemoteModuleBase + rva;
				}
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME FuncName = (PIMAGE_IMPORT_BY_NAME)(LocalImageData + OriginalThunkData->u1.AddressOfData);
				
				if (IsLoaded)
					FuncAddress = GetProcAddressByName(LocalModule, (const char*)FuncName->Name, PathExe);
				else
				{
					DWORD rva = GetProcRVAByName(LocalModule, (const char*)FuncName->Name, PathExe);
					FuncAddress = RemoteModuleBase + rva;
				}
				
				if (!FuncAddress)
				{
					output = "[!] Функция " + std::string(FuncName->Name) + " была не найдена";
					return false;
				}
			}


			ThunkData->u1.Function = FuncAddress;

			++ThunkData;
			++OriginalThunkData;
		}

		++IAT;
	}
	

	return true;
}