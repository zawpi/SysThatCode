#pragma once
#include <Windows.h>
#include <string>

#ifndef CONTAINING_RECORD
#define CONTAINING_RECORD(address, type, field) \
    ((type *)((ULONG_PTR)(address) - UFIELD_OFFSET(type, field)))
#endif

typedef struct _SYSTHAT_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} SYSTHAT_UNICODE_STRING;

typedef struct _SYSTHAT_PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} SYSTHAT_PEB_LDR_DATA;

typedef struct _SYSTHAT_PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    _SYSTHAT_PEB_LDR_DATA* Ldr;
} SYSTHAT_PEB;

typedef struct _SYSTHAT_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    SYSTHAT_UNICODE_STRING FullDllName;
    SYSTHAT_UNICODE_STRING BaseDllName;
} SYSTHAT_LDR_DATA_TABLE_ENTRY;

inline int __strlen(const char* str)
{
    const char* s;
    for (s = str; *s; ++s);
    return (int)(s - str);
}

inline unsigned int __strncmp(const char* s1, const char* s2, size_t n)
{
    if (n == 0)
        return 0;
    do
    {
        if (*s1 != *s2++)
            return (*(unsigned char*)s1 - *(unsigned char*)--s2);
        if (*s1++ == 0)
            break;
    } while (--n != 0);
    return 0;
}

inline int __wcslen(const wchar_t* str)
{
    int counter = 0;
    if (!str)
        return 0;
    for (; *str != L'\0'; ++str)
        ++counter;
    return counter;
}

inline int __wcsicmp_i(const wchar_t* cs, const wchar_t* ct)
{
    int len_cs = __wcslen(cs);
    int len_ct = __wcslen(ct);

    if (len_cs < len_ct)
        return 0;

    for (int i = 0; i <= len_cs - len_ct; i++)
    {
        bool match = true;

        for (int j = 0; j < len_ct; j++)
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
            return 1;
    }

    return 0;
}

inline SYSTHAT_PEB* GetPEB()
{
#ifdef _WIN64
    return (SYSTHAT_PEB*)__readgsqword(0x60);
#else
    return (SYSTHAT_PEB*)__readfsdword(0x30);
#endif
}

inline void* FindExport(uintptr_t ModuleBase, IMAGE_EXPORT_DIRECTORY* Table, const char* FunctionToSearch)
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

inline IMAGE_EXPORT_DIRECTORY* GetExportTable(uintptr_t ModuleBase)
{
    if (!ModuleBase) return nullptr;
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

inline uintptr_t GetModuleHandleWSafe(const wchar_t* ModuleName)
{
    SYSTHAT_PEB* Peb = GetPEB();

    _SYSTHAT_PEB_LDR_DATA* PebLdr = Peb->Ldr;
    LIST_ENTRY* Head = &PebLdr->InLoadOrderModuleList;
    LIST_ENTRY* Current = Head->Flink;

    while (Current && Current != Head)
    {
        auto entry = CONTAINING_RECORD(Current, SYSTHAT_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if (entry->BaseDllName.Buffer && __wcsicmp_i(entry->BaseDllName.Buffer, ModuleName))
        {
            return reinterpret_cast<uintptr_t>(entry->DllBase);
        }

        Current = Current->Flink;
    }

    return 0;
}

inline void* GetProcAddressSafe(uintptr_t ModuleBase, const char* funcName)
{
    IMAGE_EXPORT_DIRECTORY* ExportTable = GetExportTable(ModuleBase);
    void* funcAddr = FindExport(ModuleBase, ExportTable, funcName);

    return funcAddr;
}

inline DWORD GetSyscallIDXFromAddr(uintptr_t FuncAddr)
{
    return *(unsigned long*)((FuncAddr + 4));
}

inline DWORD GetSyscallIDX(const std::string& moduleName, const std::string& funcName)
{
    std::wstring wide(moduleName.begin(), moduleName.end());
    const wchar_t* wstr = wide.c_str();
    uintptr_t funcAdress = (uintptr_t)GetProcAddressSafe(GetModuleHandleWSafe(wstr), funcName.c_str());
    return GetSyscallIDXFromAddr(funcAdress);
}
