#include "include/common/memtools.hpp"

namespace exploit
{
    namespace memtools
    {
        unsigned long long ulGetKernelBase(PCHAR ModuleName) {
            PVOID kernelImageBase = NULL;
            PCHAR kernelImage = NULL;


            //import function `NtQuerySystemInformation`
            HMODULE ntdll = GetModuleHandle(TEXT("ntdll"));
            PNtQuerySystemInformation NtQuerySystemInformation = (PNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
            if (NtQuerySystemInformation == NULL) {
                printf("[!] GetProcAddress() failed.\n");
                return 0;
            }

            //init length
            ULONG len = 0;
            NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &len);
            //init module infomations
            PSYSTEM_MODULE_INFORMATION pModuleInfo = (PSYSTEM_MODULE_INFORMATION)GlobalAlloc(GMEM_ZEROINIT, len);
            if (pModuleInfo == NULL) {
                printf("[!] [ulGetKernelBase]  Could not allocate memory for module info.\n");
                return 0;
            }

            //starting quering
            NTSTATUS status = NtQuerySystemInformation(SystemModuleInformation, pModuleInfo, len, &len);

            if (status != (NTSTATUS)0x0) {
                printf("[!] [ulGetKernelBase] NtQuerySystemInformation failed with error code 0x%X\n", status);
                return 0;
            }
            for (unsigned int i = 0; i < pModuleInfo->ModulesCount; i++) {
                kernelImage = (PCHAR)pModuleInfo->Modules[i].Name;
                if (strstr(kernelImage, ModuleName)) {
                    kernelImageBase = pModuleInfo->Modules[i].ImageBaseAddress;
                    printf("[*] [ulGetKernelBase]  Mod name %s ", kernelImage);
                    printf(" Base Addr 0x%llx\r\n", kernelImageBase);

                    return (unsigned long long)kernelImageBase;
                }
            }
            return 0;
        }
    } // namespace memtools

} // namespace exploit