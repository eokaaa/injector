#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <string>

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