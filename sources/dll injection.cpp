#include "../imgui/imgui.h"
#include "../imgui/imgui_impl_win32.h"
#include "../imgui/imgui_impl_dx11.h"

#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <fstream>
#include <vector>

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

