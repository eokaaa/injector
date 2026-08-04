#include "../../imgui/imgui.h"
#include "../../imgui/imgui_impl_win32.h"
#include "../../imgui/imgui_impl_dx11.h"

#include "ParseModules.h"
#include "dll injection.h"

/*
bool LoadLibraryDllInject(DWORD pid, std::wstring& directoryPath, std::string& output)
{
	if (directoryPath.empty())
	{
		output = "[!] При проверки dll произошла ошибка.";
		return false;
	}

	// открытие процесса
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
	if (!hProcess)
	{
		output = "[!] При открытии процесса возникла проблема.";
		return false;
	}

	// выделение памяти
	size_t sizeInProcessPathToDll = (directoryPath.length() + 1) * sizeof(wchar_t);
	LPVOID remoteMemory = VirtualAllocEx(hProcess, nullptr, sizeInProcessPathToDll, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!remoteMemory)
	{
		output = "[!] При выделении памяти возникла проблема.";
		VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}
	
	// запись пути dll 
	if (!WriteProcessMemory(hProcess, remoteMemory, directoryPath.c_str(), sizeInProcessPathToDll, nullptr))
	{
		output = "[!] При записи путя dll возникла проблема.";
		VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	// получаем адрес
	LPVOID loadLibrary = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
	if (!loadLibrary)
	{
		output = "[!] При получении адреса возникла ошибка.";
		VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	// создание удаленного потока, который вызывает loadLibrary с путем dll
	HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
		(LPTHREAD_START_ROUTINE)loadLibrary, remoteMemory, 0, nullptr);
	if (!hThread)
	{
		output = "[!] При создании удаленного потока возникла ошибка.";
		CloseHandle(hProcess);
		VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
		return false;
	}

	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
	CloseHandle(hProcess);

	output = "[+] Инъекция dll прошла успешно";
	return true;
}
*/


extern "C" void ShellCode(MANUAL_MAP_MAIN* pData);
extern "C" void ShellCodeEnd();

uintptr_t ManualMapDllInject(DWORD pid, std::wstring PathDll, std::string& output, std::wstring PathExe)
{
	MappedModules.clear();
	LocalImagesCache.clear();

	HANDLE hProcess;
	if (!SilentOpenProcess(pid, &hProcess))
	{
		output = "[!] При открытии процесса произошла ошибка";
		return false;
	}

	PathExe.resize(MAX_PATH);
	DWORD Size = MAX_PATH;
	if (!QueryFullProcessImageNameW(hProcess, 0, PathExe.data(), &Size))
	{
		output = "[!] Не удалось получить путь к файлу";
		SilentCloseHandle(hProcess);
		return false;
	}
	PathExe.resize(Size);	

	std::vector<uint8_t> ExeFileStruct;
	if (!GetStructFile(PathExe, ExeFileStruct))
	{
		output = "[!] Не удалось прочитать структуру [EXE]";
		SilentCloseHandle(hProcess);
		return false;
	}
	std::vector<uint8_t> DllFileStruct;
	if (!GetStructFile(PathDll, DllFileStruct))
	{
		output = "[!] Не удалось прочитать структуру [DLL]";
		SilentCloseHandle(hProcess);
		return false;
	}

	IMAGE_DOS_HEADER* ExeImageDOS = reinterpret_cast<IMAGE_DOS_HEADER*>(ExeFileStruct.data());
	IMAGE_NT_HEADERS* ExeImageNT  = reinterpret_cast<IMAGE_NT_HEADERS*>(ExeFileStruct.data() + ExeImageDOS->e_lfanew);
	if (ExeImageDOS->e_magic != IMAGE_DOS_SIGNATURE ||
		ExeImageNT->Signature != IMAGE_NT_SIGNATURE)
	{
		output = "[!] Это не PE структура [EXE]";
		SilentCloseHandle(hProcess);
		return false;
	}

	IMAGE_DOS_HEADER* DllImageDOS = reinterpret_cast<IMAGE_DOS_HEADER*>(DllFileStruct.data());
	IMAGE_NT_HEADERS* DllImageNT = reinterpret_cast<IMAGE_NT_HEADERS*>(DllFileStruct.data() + DllImageDOS->e_lfanew);
	if (DllImageDOS->e_magic != IMAGE_DOS_SIGNATURE ||
		DllImageNT->Signature != IMAGE_NT_SIGNATURE)
	{
		output = "[!] Это не PE структура [DLL]";
		SilentCloseHandle(hProcess);
		return false;
	}

	if (DllImageNT->FileHeader.Machine != ExeImageNT->FileHeader.Machine)
	{
		output = "[!] Архитектура должна совпадать";
		SilentCloseHandle(hProcess);
		return false;
	}

	uintptr_t DllImageBase = 0;
	size_t  DllSizeOfImage = 0;
	size_t  DllSizeOfHeaders = 0;
	uintptr_t DllEntryPoint = 0;

	IMAGE_DATA_DIRECTORY RelocData;
	IMAGE_DATA_DIRECTORY ImportData;
	IMAGE_DATA_DIRECTORY TLSData;
	IMAGE_DATA_DIRECTORY ExceptionData;

	bool DllIs64 = (DllImageNT->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

	if (DllIs64)
	{
		auto DllImageNT64 = (IMAGE_NT_HEADERS64*)DllImageNT;
		DllImageBase = DllImageNT64->OptionalHeader.ImageBase;
		DllSizeOfImage = DllImageNT64->OptionalHeader.SizeOfImage;
		DllSizeOfHeaders = DllImageNT64->OptionalHeader.SizeOfHeaders;
		DllEntryPoint = DllImageNT64->OptionalHeader.AddressOfEntryPoint;

		RelocData = DllImageNT64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		ImportData = DllImageNT64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		TLSData = DllImageNT64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
		ExceptionData = DllImageNT64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	}
	else
	{
		auto DllImageNT32 = (IMAGE_NT_HEADERS32*)DllImageNT;
		DllImageBase = DllImageNT32->OptionalHeader.ImageBase;
		DllSizeOfImage = DllImageNT32->OptionalHeader.SizeOfImage;
		DllSizeOfHeaders = DllImageNT32->OptionalHeader.SizeOfHeaders;
		DllEntryPoint = DllImageNT32->OptionalHeader.AddressOfEntryPoint;

		RelocData = DllImageNT32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		ImportData = DllImageNT32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		TLSData = DllImageNT32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
		ExceptionData = DllImageNT32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	}

	PVOID pBaseAddress = NULL;
	
	LPVOID VirtualAllocateDll = SilentAllocate(hProcess, &pBaseAddress, 0, &DllSizeOfImage, MEM_COMMIT | MEM_RESERVE);
	if (!VirtualAllocateDll)
	{
		output = "[!] Не удалось выделить память для dll";
		SilentCloseHandle(hProcess);
		return false;
	}

	uintptr_t MemoryAllocate = reinterpret_cast<uintptr_t>(VirtualAllocateDll);

	std::vector<uint8_t> LocalImage(DllSizeOfImage, 0);
	std::memcpy(LocalImage.data(), DllFileStruct.data(), DllSizeOfHeaders);

	IMAGE_SECTION_HEADER* Sections = IMAGE_FIRST_SECTION(DllImageNT);
	for (int i = 0; i < DllImageNT->FileHeader.NumberOfSections; ++i, ++Sections)
	{
		if (Sections->SizeOfRawData > 0 && Sections->PointerToRawData > 0)
		{
			std::memcpy(
				LocalImage.data() + Sections->VirtualAddress,
				DllFileStruct.data() + Sections->PointerToRawData,
				Sections->SizeOfRawData
			);
		}
	}

	uintptr_t LocalImageData = reinterpret_cast<uintptr_t>(LocalImage.data());

	if (!ParseReloc(MemoryAllocate, DllImageBase, LocalImageData, RelocData))
	{
		output = "[!] Ошибка при парсинге .reloc";
		SilentFreeAllocate(hProcess, &VirtualAllocateDll);
		SilentCloseHandle(hProcess);
		return false;
	}


	if (!ParseImports(ImportData, LocalImageData, DllSizeOfImage, hProcess, PathDll, output, PathExe))
	{
		output = "[!] Ошибка при парсинге импортов";
		SilentFreeAllocate(hProcess, &VirtualAllocateDll);
		SilentCloseHandle(hProcess);
		return false;
	}

	if (!SilentWriteProcess(hProcess, VirtualAllocateDll, LocalImage.data(), DllSizeOfImage, 0))
	{
		output = "[!] Ошибка при записи заголовка";
		SilentFreeAllocate(hProcess, &VirtualAllocateDll);
		SilentCloseHandle(hProcess);
		return false;
	}

	ULONG OldProtect = 0;
	SilientProtectMemory(hProcess, &VirtualAllocateDll, DllSizeOfImage, PAGE_EXECUTE_READWRITE, &OldProtect);

	DWORD TID = GetThreadID(pid);
	HANDLE hThread;
	if (!SilentOpenThread(TID, &hThread))
	{
		output = "[!] При открытии потока произошла ошибка";
		SilentFreeAllocate(hProcess, &VirtualAllocateDll);
		CloseHandle(hProcess);
		return false;
	}

	ULONG SuspendCount = INFINITE;

	SilentSuspendThread(hThread);

	CONTEXT ContextThread;
	ContextThread.ContextFlags = CONTEXT_FULL;

	if (!SilentGetContextThread(hThread, &ContextThread))
	{
		output = "[!] При получении контекста потока произошла ошибка";
		SilentFreeAllocate(hProcess, &VirtualAllocateDll);
		CloseHandle(hProcess);
		return false;
	}

	MANUAL_MAP_MAIN MapData = {};
	IMAGE_DATA_DIRECTORY ExceptionDir = DllImageNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

	MapData.HinstDLL = (HINSTANCE)VirtualAllocateDll;
	MapData.FdwReason = DLL_PROCESS_ATTACH;
	MapData.lpvReserved = nullptr;
	MapData.EntryPoint = DllEntryPoint;
	MapData.Done = 0;
	if (ExceptionData.VirtualAddress != 0 && ExceptionData.Size != 0)
	{
		MapData.FunctionTable = (PVOID)(MemoryAllocate + ExceptionDir.VirtualAddress);
		MapData.EntryCount = ExceptionDir.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
		MapData.BaseAddress = (PVOID)MemoryAllocate;
		MapData.RtlAddFunctionTable = (PVOID)GetProcAddressByName(SilentSearchDll("ntdll.dll"), "RtlAddFunctionTable", PathExe);
	}

	if (TLSData.Size != 0 && TLSData.VirtualAddress != 0)
	{
		auto pTLS = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(LocalImageData + TLSData.VirtualAddress);
		if (pTLS->AddressOfCallBacks != 0)
		{
			ULONG_PTR RVA = pTLS->AddressOfCallBacks - DllImageBase;
			MapData.TLSCallbacks = pTLS->AddressOfCallBacks;
		}
	}

	if (!MapData.RtlAddFunctionTable || !MapData.TLSCallbacks)
	{
		output = "[!] RtlAddFunctionTable/TLSCallbacks не найдена";
		return false;
	}


	size_t ShellCodeSize = (uintptr_t)ShellCodeEnd - (uintptr_t)ShellCode;
	size_t ParamSize = sizeof(MANUAL_MAP_MAIN);
	size_t TotalSize = (ShellCodeSize + ParamSize);

	PVOID pBaseAddressShellCode = NULL;

	LPVOID ShellCodeAlloc = SilentAllocate(hProcess, &pBaseAddressShellCode, 0, &TotalSize, MEM_COMMIT | MEM_RESERVE);
	if (!ShellCodeAlloc)
	{
		output = "[!] Не удалось выделить память для шеллкода";
		SilentFreeAllocate(hProcess, &VirtualAllocateDll);
		CloseHandle(hProcess);
		return false;
	}

	LPVOID ParamAlloc = (LPVOID)((uintptr_t)ShellCodeAlloc + ShellCodeSize);

	if (!SilentWriteProcess(hProcess, ShellCodeAlloc, (void*)ShellCode, ShellCodeSize, 0) ||
		!SilentWriteProcess(hProcess, ParamAlloc, &MapData, ParamSize, 0))
	{
		output = "[!] Ошибка при записи шеллкода или параметров";
		SilentFreeAllocate(hProcess, &ShellCodeAlloc);
		SilentFreeAllocate(hProcess, &VirtualAllocateDll);
		CloseHandle(hProcess);
		return false;
	}

	SilientProtectMemory(hProcess, &ShellCodeAlloc, TotalSize, PAGE_EXECUTE_READWRITE, &OldProtect);

	uintptr_t RIP = ContextThread.Rip;

	ContextThread.Rcx = (uintptr_t)ParamAlloc;
	ContextThread.Rsp &= ~0xFull;
	ContextThread.Rsp -= 0x8;
	ContextThread.Rip = (uintptr_t)ShellCodeAlloc;

	SilentWriteProcess(hProcess, (PVOID)ContextThread.Rsp, &RIP, sizeof(uintptr_t), 0);

	if (!SilentSetContextThread(hThread, &ContextThread))
	{
		output = "[!] Ошибка при установке контекста";
		SilentFreeAllocate(hProcess, &ShellCodeAlloc);
		SilentFreeAllocate(hProcess, &VirtualAllocateDll);
		CloseHandle(hProcess);
		return false;
	}

	SilentResumeThread(hThread);

	DWORD done = 0;
	SIZE_T BytesRead = 0;
	while (!done)
	{
		BytesRead = 0;
		SilentReadProcess(hProcess, (PVOID)((uintptr_t)ParamAlloc + offsetof(MANUAL_MAP_MAIN, Done)), &done, sizeof(DWORD), &BytesRead);
		Sleep(10);
	}
	Sleep(150);

	std::vector<uint8_t> ZeroBuffer(DllSizeOfHeaders, 0);
	SilientProtectMemory(hProcess, &VirtualAllocateDll, DllSizeOfHeaders, PAGE_READWRITE, &OldProtect);
	SilentWriteProcess(hProcess, VirtualAllocateDll, ZeroBuffer.data(), DllSizeOfHeaders, 0);
	SilientProtectMemory(hProcess, &VirtualAllocateDll, DllSizeOfHeaders, OldProtect, &OldProtect);

	SilentFreeAllocate(hProcess, &ShellCodeAlloc);

	SilentCloseHandle(hThread);
	SilentCloseHandle(hProcess);
	output = "[+] DLL была успешно внедрена в EXE";
	return MemoryAllocate;
}