# SysThatCode

This library allows you to get the syscall ID of functions exported by `ntdll.dll` without using any WIN API.

What the code does:  
- Accesses the Process Environment Block (PEB) to locate `ntdll.dll` base address.  
- Parses the export table to find function addresses.  
- Extracts syscall ID from the function prologue for direct syscall usage.

## Usage

1. Include the header file `SysThatCode.h` in your project.  
2. Call `GetSysCode("FunctionName")` with the desired `ntdll.dll` function name.  
3. The function returns the syscall ID associated with that function.

Example:

```cpp
#include "SysThatCode.h"
#include <iostream>

int main() {
    std::string funcName = "NtOpenProcess";
    DWORD syscallID = GetSysCode(funcName);
    std::cout << "Syscall ID: " << syscallID << std::endl;
    return 0;
}
