#include "SysThatCode.h"
#include <iostream>

int main() {
	std::cout << "Name of the function: ";
	std::string input;
	std::cin >> input;

	DWORD syscallId = GetSyscallId(input);
	std::cout << "Syscall ID : "<< syscallId << std::endl;

	std::cout << "Press Enter to exit...\n";
	std::cin.ignore();
	std::cin.get();
}
