#pragma once

#include "ParseModules.h"

#pragma comment(lib, "ntdll.lib")


typedef struct _FULL_LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	PVOID SectionPointer;
	ULONG CheckSum;
	ULONG TimeDateStamp;
} FULL_LDR_DATA_TABLE_ENTRY, * PFULL_LDR_DATA_TABLE_ENTRY;

typedef struct _FULL_PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} FULL_PEB_LDR_DATA, * PFULL_PEB_LDR_DATA;

typedef struct _MY_RTL_USER_PROCESS_PARAMETERS
{
	ULONG MaximumLength;          // 0x0
	ULONG Length;                 // 0x4
	ULONG Flags;                  // 0x8
	ULONG DebugFlags;             // 0xc
	VOID* ConsoleHandle;          // 0x10
	VOID* StandardInput;          // 0x20
	VOID* StandardOutput;         // 0x28
	VOID* StandardError;          // 0x30

	BYTE PADDING[0x28];

	struct _UNICODE_STRING ImagePathName; // 0x60
	struct _UNICODE_STRING CommandLine; // 0x70
	VOID* Environment;            // 0x80
} MY_RTL_USER_PROCESS_PARAMETERS, * MY_PRTL_USER_PROCESS_PARAMETERS;


typedef struct _FILE_BASIC_INFORMATION
{
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	ULONG FileAttributes;
} FILE_BASIC_INFORMATION, * PFILE_BASIC_INFORMATION;

typedef NTSTATUS(NTAPI* pfnNtQueryAttributesFile)(
	POBJECT_ATTRIBUTES ObjectAttributes,
	PFILE_BASIC_INFORMATION FileInformation
);