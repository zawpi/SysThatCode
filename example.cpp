#include "SysThatCode.h"
#include <iostream>

int main() {
    std::string funcName = "NtOpenProcess";
    DWORD syscallID = GetSysCode(funcName);
    std::cout << "Syscall ID: " << syscallID << std::endl;
    return 0;
}
