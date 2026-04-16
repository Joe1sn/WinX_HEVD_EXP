#pragma once
#include "include/common/shellcode.hpp"
#include "include/common/memtools.hpp"
#include "include/common/gadget.hpp"
#include <Windows.h>
#include <iostream>
#include <cstdio>
namespace exploit
{
    typedef unsigned long long funcaddr;
    namespace stackoverflow
    {
        void StackOverflow(HANDLE hDevice, unsigned int ioctl);
        void StackOverflowGS(HANDLE hDevice, unsigned int ioctl);
    } // namespace stackoverflow

} // namespace exploit