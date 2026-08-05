#include "ParseModules.h"
#include "DLLInjection.h"

#include "sources/Utils/Utils.h"

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

	if (!ParseImports(ImportData, LocalImageData, DllSizeOfImage, hProcess, PathDll, output, PathExe))
		return false;

	LocalImagesCache[NameDll] = std::move(LocalImage);

	if (!SilentWriteProcess(hProcess, VirtualAllocateDll, LocalImagesCache[NameDll].data(), DllSizeOfImage, 0))
		return false;

	ULONG OldProtect = 0;
	SilentProtectMemory(hProcess, &VirtualAllocateDll, DllSizeOfImage, PAGE_EXECUTE_READWRITE, &OldProtect);

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

			RemoteModuleBase = MapModules(hProcess, DepFileStruct, PathExe, DifferentPathDll, NameDll, output);
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