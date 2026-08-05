#pragma once

#include <windows.h>
#include <d3d11.h>
#include <string>
#include <vector>

struct ProcessInfo 
{
    DWORD pid;
    std::string name;
    std::string displayName;
    ID3D11ShaderResourceView* iconTexture = nullptr;
};

bool GetStructFile(std::wstring& wstr, std::vector<uint8_t>& FileStruct);
bool CreateLocalImage(std::vector<uint8_t>& LocalImage, std::vector<uint8_t>& ExternImage);

std::vector<ProcessInfo> getRunningProcesses(ID3D11Device* pd3dDevice);
void freeProcessList(std::vector<ProcessInfo>& list);
std::wstring openFileDialogForExe(HWND hwnd);
std::wstring escapeBackslashes(const std::wstring& path);
DWORD findProcessPID(const std::wstring& directoryPath);

std::wstring openFileDialogForDll(HWND hwnd);
std::string wstringToUtf8(const std::wstring& wstr);
std::wstring utf8ToWstring(const std::string& str);