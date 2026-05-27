#pragma once
#include <Windows.h>
#include <vector>
#include "include/common/shellcode.hpp"
#include "include/common/memtools.hpp"
#include "include/common/gadget.hpp"
#include "include/exp/exploit.hpp"

namespace exploit
{
    typedef unsigned long long funcaddr;
    namespace arbitrary
    {
        typedef struct _args {
            PVOID what;
            PVOID where;
        }args, * pArgs;

        void write(HANDLE hDevice, unsigned int ioctl);
    } // namespace stackoverflow

} // namespace exploit