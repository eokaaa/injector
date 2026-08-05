#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <codecvt>

#include <psapi.h>
#include <shellapi.h>
#include <algorithm>
#include <unordered_set>
#include <fstream>

#include "Utils.h"

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

static ID3D11ShaderResourceView* CreateTextureFromHICON(ID3D11Device* pd3dDevice, HICON hIcon)
{
    if (!pd3dDevice || !hIcon) return nullptr;

    const int width = 16;
    const int height = 16;

    HDC hdcScreen = GetDC(NULL);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);

    BITMAPINFO bmi = {};
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = width;
    bmi.bmiHeader.biHeight = -height;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;

    void* pBits = nullptr;
    HBITMAP hBitmap = CreateDIBSection(hdcMem, &bmi, DIB_RGB_COLORS, &pBits, NULL, 0);
    if (!hBitmap)
    {
        DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScreen);
        return nullptr;
    }

    HGDIOBJ hOldBmp = SelectObject(hdcMem, hBitmap);
    ZeroMemory(pBits, width * height * 4);
    DrawIconEx(hdcMem, 0, 0, hIcon, width, height, 0, NULL, DI_NORMAL);

    D3D11_TEXTURE2D_DESC desc = {};
    desc.Width = width;
    desc.Height = height;
    desc.MipLevels = 1;
    desc.ArraySize = 1;
    desc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    desc.SampleDesc.Count = 1;
    desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;

    D3D11_SUBRESOURCE_DATA initData = {};
    initData.pSysMem = pBits;
    initData.SysMemPitch = width * 4;

    ID3D11Texture2D* pTexture = nullptr;
    ID3D11ShaderResourceView* pSRV = nullptr;

    if (SUCCEEDED(pd3dDevice->CreateTexture2D(&desc, &initData, &pTexture)))
    {
        pd3dDevice->CreateShaderResourceView(pTexture, NULL, &pSRV);
        pTexture->Release();
    }

    SelectObject(hdcMem, hOldBmp);
    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);

    return pSRV;
}

static HICON GetProcessIcon(DWORD pid)
{
    HICON hIcon = NULL;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess)
    {
        wchar_t exePath[MAX_PATH] = { 0 };
        if (GetModuleFileNameExW(hProcess, NULL, exePath, MAX_PATH))
        {
            SHFILEINFOW shfi = { 0 };
            if (SHGetFileInfoW(exePath, 0, &shfi, sizeof(shfi), SHGFI_ICON | SHGFI_SMALLICON) && shfi.hIcon)
            {
                hIcon = shfi.hIcon;
            }
        }
        CloseHandle(hProcess);
    }
    if (!hIcon)
    {
        hIcon = LoadIcon(NULL, IDI_APPLICATION);
    }
    return hIcon;
}

void freeProcessList(std::vector<ProcessInfo>& list)
{
    for (auto& proc : list)
    {
        if (proc.iconTexture)
        {
            proc.iconTexture->Release();
            proc.iconTexture = nullptr;
        }
    }
    list.clear();
}

std::vector<ProcessInfo> getRunningProcesses(ID3D11Device* pd3dDevice)
{
    std::vector<ProcessInfo> list;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return list;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    std::unordered_set<std::string> seenNames;

    if (Process32FirstW(snapshot, &pe32))
    {
        do
        {
            if (pe32.th32ProcessID == 0 || pe32.th32ProcessID == 4) continue;

            std::string name = wstringToUtf8(pe32.szExeFile);
            std::string nameLower = name;
            std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);

            if (seenNames.find(nameLower) != seenNames.end())
                continue;

            seenNames.insert(nameLower);

            ProcessInfo info;
            info.pid = pe32.th32ProcessID;
            info.name = name;
            info.displayName = info.name + "  (PID: " + std::to_string(info.pid) + ")";

            HICON hIcon = GetProcessIcon(info.pid);
            if (hIcon)
            {
                info.iconTexture = CreateTextureFromHICON(pd3dDevice, hIcon);
                DestroyIcon(hIcon);
            }

            list.push_back(info);
        } while (Process32NextW(snapshot, &pe32));
    }

    CloseHandle(snapshot);

    std::sort(list.begin(), list.end(), [](const ProcessInfo& a, const ProcessInfo& b) {
        return _stricmp(a.name.c_str(), b.name.c_str()) < 0;
    });

    return list;
}

std::wstring openFileDialogForExe(HWND hwnd)
{
	wchar_t fileName[MAX_PATH] = L"\0";

	OPENFILENAME ofn;
	ZeroMemory(&ofn, sizeof(ofn));

	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = hwnd;
	ofn.lpstrFilter = L"EXE file (*.exe)\0*.exe\0\0";
	ofn.lpstrFile = fileName;
	ofn.nMaxFile = MAX_PATH;
	ofn.Flags = OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;
	ofn.lpstrDefExt = L".exe";

	if (GetOpenFileNameW(&ofn))
	{
		std::wstring path = fileName;
		return fileName;
	}
	return L"";
}

std::wstring escapeBackslashes(const std::wstring& path) 
{
	std::wstring escaped;
	for (wchar_t ch : path) {
		if (ch == L'\\') {
			escaped += L"\\\\";
		}
		else {
			escaped += ch;
		}
	}
	return escaped;
}

DWORD findProcessPID(const std::wstring& directoryPath)
{
	DWORD pid = 0;

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE) return 0;

	PROCESSENTRY32 process32;
	process32.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(snapshot, &process32))
	{
		do
		{
			HANDLE openProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, false, process32.th32ProcessID);
			if (openProcess)
			{
				wchar_t exePath[MAX_PATH];
				if (GetModuleFileNameExW(openProcess, NULL, exePath, MAX_PATH))
				{
					std::wstring currentPath = exePath;

					if (_wcsicmp(currentPath.c_str(), directoryPath.c_str()) == 0)
					{
						pid = process32.th32ProcessID;
						CloseHandle(openProcess);
						break;
					}
				}
				CloseHandle(openProcess);
			}

		} while (Process32Next(snapshot, &process32));
	}

	CloseHandle(snapshot);
	return pid;
}

std::wstring openFileDialogForDll (HWND hwnd)
{
	wchar_t fileName[MAX_PATH] = L"\0";

	OPENFILENAME ofn;
	ZeroMemory(&ofn, sizeof(ofn));

	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = hwnd;
	ofn.lpstrFilter = L"DLL file (*.dll)\0*.dll\0\0";
	ofn.lpstrFile = fileName;
	ofn.nMaxFile = MAX_PATH;
	ofn.Flags = OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;
	ofn.lpstrDefExt = L".dll";

	if (GetOpenFileNameW(&ofn))
	{
		std::wstring path = fileName;
		return fileName;
	}
	return L"";
}

std::string wstringToUtf8(const std::wstring& wstr) 
{
	if (wstr.empty()) return std::string();
	int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), nullptr, 0, nullptr, nullptr);
	std::string result(size_needed, 0);
	WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), &result[0], size_needed, nullptr, nullptr);
	return result;
}

std::wstring utf8ToWstring(const std::string& str)
{
	if (str.empty()) return std::wstring();
	int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), nullptr, 0);
	std::wstring result(size_needed, 0);
	MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), &result[0], size_needed);
	return result;
}