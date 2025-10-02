#include "SysThatCode.h"
#include <iostream>

int main()
{
    std::string ModuleName = "ntdll.dll";
    std::string funcName = "NtOpenProcess";
    DWORD syscallID = GetSyscallIDX(ModuleName,funcName);
    std::cout << "Syscall index: " << syscallID << std::endl;
    return 0;
}