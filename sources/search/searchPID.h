#pragma once
#include <windows.h>
#include <d3d11.h>
#include <string>
#include <vector>

struct ProcessInfo {
    DWORD pid;
    std::string name;
    std::string displayName;
    ID3D11ShaderResourceView* iconTexture = nullptr;
};

std::vector<ProcessInfo> getRunningProcesses(ID3D11Device* pd3dDevice);
void freeProcessList(std::vector<ProcessInfo>& list);
std::wstring openFileDialogForExe(HWND hwnd);
std::wstring escapeBackslashes(const std::wstring& path);
DWORD findProcessPID(const std::wstring& directoryPath);