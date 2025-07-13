#pragma once
#include <windows.h>
#include <string>

std::wstring openFileDialogForExe(HWND hwnd);
std::wstring escapeBackslashes(const std::wstring& path);
DWORD findProcessPID(const std::wstring& directoryPath);