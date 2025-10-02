#include "SysThatCode.h"
#include <iostream>

int main()
{
    std::string funcName = "NtOpenProcess";
    DWORD syscallID = GetSyscallIDX(funcName);
    std::cout << "Syscall index: " << syscallID << std::endl;
    return 0;
}

