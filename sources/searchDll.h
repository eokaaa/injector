#pragma once

#include <windows.h>
#include <string>

std::wstring openFileDialogForDll(HWND hwnd);
std::string wstringToUtf8(const std::wstring& wstr);
std::wstring utf8ToWstring(const std::string& str);