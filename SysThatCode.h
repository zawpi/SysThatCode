#pragma once
#include <Windows.h>
#include <cstdio>
#include <iostream>
// why? just why..
// #include <winternl> 
// no?

#ifndef CONTAINING_RECORD // yippe skibidi toilet
#define CONTAINING_RECORD(address, type, field) \
    ((type *)((ULONG_PTR)(address) - UFIELD_OFFSET(type, field)))

#endif

// if you value your compile times
#ifndef SYSTHATCODE_FUNC
#define YES_DADDY_I_VALUE_MY_COMPILE_TIMES  0
#if YES_DADDY_I_VALUE_MY_COMPILE_TIMES
#define SYSTHATCODE_FUNC
#else
#define SYSTHATCODE_FUNC __forceinline
#endif
#endif

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

typedef struct _PEB {
	BYTE                          Reserved1[2];
	BYTE                          BeingDebugged;
	BYTE                          Reserved2[1];
	PVOID                         Reserved3[2];
	PPEB_LDR_DATA                 Ldr;
	void*				  		  ProcessParameters; // this is just a ptr? why not just do void* in its place so we save a few lines for this "small" library..?
	PVOID                         Reserved4[3];
	PVOID                         AtlThunkSListPtr;
	PVOID                         Reserved5;
	ULONG                         Reserved6;
	PVOID                         Reserved7;
	ULONG                         Reserved8;
	ULONG                         AtlThunkSListPtr32;
	PVOID                         Reserved9[45];
	BYTE                          Reserved10[96];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine; // same with this but i don't have compiler on me to check typedef size but it SHOULD be void* since made in browser
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

SYSTHATCODE_FUNC int __strlen(const char* str)
{
	const char* s;
	for (s = str; *s; ++s);
	return (s - str);
}

unsigned int __strncmp(const char* s1, const char* s2, size_t n)
{
	if (n == 0)
		return (0);
	do
	{
		if (*s1 != *s2++)
			return (*(unsigned char*)s1 - *(unsigned char*)--s2);
		if (*s1++ == 0)
			break;
	} while (--n != 0);
	return (0);
}	

// uh made in browser this MIGHT be wrong though.
SYSTHATCODE_FUNC int __wcslen(wchar_t* str)
{
	int counter = 0;
	if (!str)
		return 0;
	for (; *str != '\0'; ++str)
		++counter;
	return counter;
}

SYSTHATCODE_FUNC int __wcsicmp_i(wchar_t* cs, wchar_t* ct)
{
		auto len_cs = __wcslen(cs);
		auto len_ct = __wcslen(ct);

		if (len_cs < len_ct)
			return false;

		for (size_t i = 0; i <= len_cs - len_ct; i++)
		{
			bool match = true;

			for (size_t j = 0; j < len_ct; j++)
			{
				wchar_t csChar = (cs[i + j] >= L'A' && cs[i + j] <= L'Z') ? (cs[i + j] + L'a' - L'A') : cs[i + j];
				wchar_t ctChar = (ct[j] >= L'A' && ct[j] <= L'Z') ? (ct[j] + L'a' - L'A') : ct[j];

				if (csChar != ctChar)
				{
					match = false;
					break;
				}
			}

			if (match)
				return true;
		}

		return false;
}

SYSTHATCODE_FUNC void* WalkModulList(PEB_LDR_DATA* ldr) {
	LIST_ENTRY* List = &ldr->InMemoryOrderModuleList;

	LIST_ENTRY* current = List->Flink;
	while (current != List)
	{
		LDR_DATA_TABLE_ENTRY* data = (LDR_DATA_TABLE_ENTRY*)((char*)current - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));

		if (__wcsicmp_i(data->FullDllName, L"ntdll.dll")) // this is NOT a truthy as i hate those niglets
		{
			return data->DllBase;
		}
		current = current->Flink;
	}
	return nullptr;
}

SYSTHATCODE_FUNC PEB* GetPEB() // uh what the cat
{
	// mov rax, gs:[60h] 
	return (PEB*)__readgsdword(0x60);
}

SYSTHATCODE_FUNC void* FindExport(uintptr_t ModuleBase, IMAGE_EXPORT_DIRECTORY* Table, const char* FunctionToSearch)
{
	DWORD* functions = (DWORD*)((char*)ModuleBase + Table->AddressOfFunctions);
	DWORD* names = (DWORD*)((char*)ModuleBase + Table->AddressOfNames);
	WORD* nameToFunc = (WORD*)((char*)ModuleBase + Table->AddressOfNameOrdinals);

	for (DWORD i = 0; i < Table->NumberOfNames; ++i)
	{
		char* Name = (char*)ModuleBase + names[i];
		if (__strncmp(Name, FunctionToSearch, __strlen(Name)) == 0)
		{
			return (void*)((char*)ModuleBase + functions[nameToFunc[i]]);
		}
	}
	return nullptr;
}

SYSTHATCODE_FUNC IMAGE_EXPORT_DIRECTORY* GetExportTable(uintptr_t ModuleBase)
{
	if (!ModuleBase) return 0;
	IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)ModuleBase;
#ifdef _WIN64
	IMAGE_NT_HEADERS64* NtHeader = (IMAGE_NT_HEADERS64*)((char*)ModuleBase + DosHeader->e_lfanew);
#else
	IMAGE_NT_HEADERS32* NtHeader = (IMAGE_NT_HEADERS32*)((char*)ModuleBase + DosHeader->e_lfanew);
#endif

	IMAGE_DATA_DIRECTORY dataExportTable = (IMAGE_DATA_DIRECTORY)(NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	IMAGE_EXPORT_DIRECTORY* ExportTable = (IMAGE_EXPORT_DIRECTORY*)((char*)ModuleBase + dataExportTable.VirtualAddress);
	return ExportTable;
}

SYSTHATCODE_FUNC uintptr_t GetModuleHandleWSafe(const wchar_t* ModuleName)
{
 LibProt::Definitions::PEB* Peb = reinterpret_cast<LibProt::Definitions::PEB*>(LibProt::Internals::GetPEB());

    LibProt::Definitions::PPEB_LDR_DATA PebLdr = Peb->Ldr;
    LIST_ENTRY* Head = &PebLdr->InLoadOrderModuleList;
    LIST_ENTRY* Current = Head->Flink;

     while (Current && Current != Head)
     {
         auto entry = CONTAINING_RECORD(Current, LibProt::Definitions::LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if (entry->BaseDllName.Buffer && __wcsicmp_i(entry->BaseDllName.Buffer, ModuleName) == 0)
        {
            return reinterpret_cast<uintptr_t>(entry->DllBase);
         }

         Current = Current->Flink;
    }

     return 0;
}

SYSTHATCODE_FUNC void* GetProcAddressSafe(uintptr_t ModuleBase, const char* funcName)
{
	IMAGE_EXPORT_DIRECTORY* ExportTable = GetExportTable(ModuleBase);
	void* funcAddr = FindSysFunction(ExportTable, funcName);

	return funcAddr;
}

SYSTHATCODE_FUNC DWORD GetSyscallIDXFromAddr(void* funcAddr)
{
	// why? just why..
	/*
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
	*/

	// your code made me so suicidal i forked this and made this in the github browser off memory.
	// shameless self promo: 
	// nocrt getmodulehandlew https://github.com/conspiracyrip/LibProt/blob/main/LibProt.h#L681
	// nocrt getprocaddr https://github.com/conspiracyrip/LibProt/blob/main/LibProt.h#L704
	// proper syscall fetching https://github.com/conspiracyrip/LibProt/blob/main/LibProt.h#L822
	/*
	__get_syscall_idx proc
   	 	mov rax, rcx
    	add rax, 4
    	mov eax, dword ptr [rax]
    	ret
	__get_syscall_idx endp
	*/

	return *(unsigned long*)((FuncAddr + 4)); // the biblically accurate term is a unsigned long is it not?
}

SYSTHATCODE_FUNC DWORD GetSyscallIDX(const std::string& moduleName, const std::string& funcName)
{
	void* funcAdress = GetProcAddressSafe(GetModuleHandleWSafe(moduleName), funcName.c_str());
	return GetCode(funcAdress);
}

