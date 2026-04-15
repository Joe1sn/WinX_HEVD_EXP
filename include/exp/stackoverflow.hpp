#pragma once
#include <Windows.h>
#include <iostream>
#include <cstdio>
namespace exploit
{
    namespace stackoverflow
    {
        void StackOverflow(HANDLE hDevice, unsigned int ioctl);
    } // namespace stackoverflow

} // namespace exploit