# SysThatCode

This library allows you to get the syscall ID of functions exported by any module with the typical syscall prefix, without using any windows api or even linking against crt <3.

what this shit does:
- access peb/module headers to diy GetProcAddress and GetModuleHandleW
- read the syscall id directly

## Requirements
1. common sense (not sold seperately)
2. brain (sold seperately)
## Usage Example:
- if you're too lazy to read example.cpp:
- 
```cpp
#include "SysThatCode.h"
#include <iostream>

int main()
{
    constexpr const char* funcName = "NtOpenProcess"; // i hate c and crt
    DWORD SyscallIndex = GetSyscallIDX(funcName);
    printf("Syscall IDX: 0x%x!\r\n", SyscallIndex); // this example probably won't support nocrt but STILL
    return 0;
}
