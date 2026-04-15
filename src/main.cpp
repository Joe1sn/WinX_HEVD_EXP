#include <iostream>
#include <windows.h>
using std::cout;

unsigned int io2num(unsigned int ioctl_num) {
    return ((ioctl_num ^ 0x220000) >> 2) & 0xfff;
}

void menu() {
    cout << "============HEVD Hack EXP============\n";
    cout << " 1. [0x222003]****** HEVD_IOCTL_BUFFER_OVERFLOW_STACK ******\n";
    cout << "input io ctl> ";
}

int main()
{
    HANDLE hDevice = NULL;
    hDevice = CreateFileW(L"\\\\.\\My1DeviceLinker", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        cout << "Error Create File\n";
        return 0;
    }

    unsigned int io_ctl = 0;
    menu();
    scanf_s("%x", &io_ctl);
    printf("%x, %x", io_ctl, io2num(io_ctl));

    switch (io_ctl)
    {
    case 1: {
        cout << "Now Excuting ...\n";
        cout << "1. [0x222003]****** HEVD_IOCTL_BUFFER_OVERFLOW_STACK ****** ...\n";
        //
        // EXP FUNCTION HERE
        //
    }
    default:
        break;
    }
}