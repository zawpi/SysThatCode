#pragma once
#include <Windows.h>
#include <cstdio>
#include <iostream>

typedef VOID(*PPS_POST_PROCESS_INIT_ROUTINE) (VOID);
typedef struct _PEB_LDR_DATA {
	BYTE       Reserved1[8];
	PVOID      Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE           Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
	BYTE                          Reserved1[2];
	BYTE                          BeingDebugged;
	BYTE                          Reserved2[1];
	PVOID                         Reserved3[2];
	PPEB_LDR_DATA                 Ldr;
	PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
	PVOID                         Reserved4[3];
	PVOID                         AtlThunkSListPtr;
	PVOID                         Reserved5;
	ULONG                         Reserved6;
	PVOID                         Reserved7;
	ULONG                         Reserved8;
	ULONG                         AtlThunkSListPtr32;
	PVOID                         Reserved9[45];
	BYTE                          Reserved10[96];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE                          Reserved11[128];
	PVOID                         Reserved12[1];
	ULONG                         SessionId;
} PEB, * PPEB;

typedef struct _LDR_DATA_TABLE_ENTRY {
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
	PVOID EntryPoint;
	PVOID Reserved3;
	UNICODE_STRING FullDllName;
	BYTE Reserved4[8];
	PVOID Reserved5[3];
	union {
		ULONG CheckSum;
		PVOID Reserved6;
	};
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


void* BaseNtdll = nullptr;

inline bool CompareBaseDllName(UNICODE_STRING fullName, const wchar_t* targetName)
{
	WCHAR* buffer = fullName.Buffer;
	int length = fullName.Length / sizeof(WCHAR);

	int lastSlash = -1;
	for (int i = length - 1; i >= 0; i--) {
		if (buffer[i] == L'\\') {
			lastSlash = i;
			break;
		}
	}

	WCHAR* baseName = (lastSlash == -1) ? buffer : buffer + lastSlash + 1;
	int baseNameLen = length - (lastSlash + 1);

	wchar_t nameBuffer[256] = { 0 };

	wcsncpy_s(nameBuffer, baseName, baseNameLen);

	return (_wcsicmp(nameBuffer, targetName) == 0);
}

inline void* WalkModulList(PEB_LDR_DATA* ldr) {
	LIST_ENTRY* List = &ldr->InMemoryOrderModuleList;

	LIST_ENTRY* current = List->Flink;
	while (current != List)
	{
		LDR_DATA_TABLE_ENTRY* data = (LDR_DATA_TABLE_ENTRY*)((char*)current - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));

		if (CompareBaseDllName(data->FullDllName, L"ntdll.dll"))
		{
			return data->DllBase;
		}
		current = current->Flink;
	}
	return nullptr;
}

inline PEB* GetPEB() {
	return (PEB*)__readgsdword(0x60);
}

inline void* FindSysFunction(IMAGE_EXPORT_DIRECTORY* Table, const char* FunctionToSearch)
{
	DWORD* functions = (DWORD*)((char*)BaseNtdll + Table->AddressOfFunctions);
	DWORD* names = (DWORD*)((char*)BaseNtdll + Table->AddressOfNames);
	WORD* nameToFunc = (WORD*)((char*)BaseNtdll + Table->AddressOfNameOrdinals);

	for (DWORD i = 0; i < Table->NumberOfNames; ++i)
	{
		char* Name = (char*)BaseNtdll + names[i];
		if (strcmp(Name, FunctionToSearch) == 0)
		{
			return (void*)((char*)BaseNtdll + functions[nameToFunc[i]]);
		}
	}
	return nullptr;
}

inline bool InitNtdll() {
	PEB* PEB = GetPEB();
	BaseNtdll = WalkModulList(PEB->Ldr);
	if (!BaseNtdll) {
		return false;
	}
	return true;
}

inline IMAGE_EXPORT_DIRECTORY* GetExportTable() {

	if (!BaseNtdll) return NULL;
	IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)BaseNtdll;
#ifdef _WIN64
	IMAGE_NT_HEADERS64* NtHeader = (IMAGE_NT_HEADERS64*)((char*)BaseNtdll + DosHeader->e_lfanew);
#else
	IMAGE_NT_HEADERS32* NtHeader = (IMAGE_NT_HEADERS32*)((char*)BaseNtdll + DosHeader->e_lfanew);
#endif

	IMAGE_DATA_DIRECTORY dataExportTable = (IMAGE_DATA_DIRECTORY)(NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	IMAGE_EXPORT_DIRECTORY* ExportTable = (IMAGE_EXPORT_DIRECTORY*)((char*)BaseNtdll + dataExportTable.VirtualAddress);
	return ExportTable;
}

inline void* GetSysFunction(const char* funcName) {
	InitNtdll();
	IMAGE_EXPORT_DIRECTORY* ExportTable = GetExportTable();
	void* funcAddr = FindSysFunction(ExportTable, funcName);

	return funcAddr;
}

inline DWORD GetCode(void* funcAddr) {
	if (!funcAddr) {
		return NULL;
	}
	BYTE* code = (BYTE*)funcAddr;

	for (int i = 0; i < 10; i++) {
		if (code[i] == 0xB8) {
			DWORD syscallId = *(DWORD*)(code + i + 1);
			return syscallId;
		}
	}
	return 0;
}

inline DWORD GetSyscallId(const std::string& funcName)
{
	void* funcAdress = GetSysFunction(funcName.c_str());
	return GetCode(funcAdress);
}
