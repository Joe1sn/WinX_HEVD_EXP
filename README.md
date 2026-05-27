# HEVD WinX Exploit 

![image-20260416153616179](.\assets\image-20260416153616179.png)

HEVD Exploit on Windows 10 2022.19045.2006

All shellcode source `.asm` at: https://github.com/Joe1sn/WinKernelShellcode/

```
D:.
├───include
│   ├───common  // gadget, find kernal base, shellcode
│   └───exp     // real exp
└───src
    ├───common
    └───exp
```

Detail writeup is in chinese:

1. [【Win Pwn】HEVD-内核栈溢出(上)](https://joe1sn.eu.org/2024/01/25/win-hevd-exp-stackoverflow-I/)

   This part is mainly about environment work and some preparations.

2. [【Win Pwn】HEVD-内核栈溢出(中)](https://joe1sn.eu.org/2024/01/25/win-hevd-exp-stackoverflow-II)

   Shows basic exploit, bypass SMEP, shutdown KVAS to test exp.

3. [【Win Pwn】HEVD-内核栈溢出(下)](https://joe1sn.eu.org/2024/01/25/win-hevd-exp-stackoverflow-III)

   More detail about shellcode writing, spawn token, ROP to bypass SMEP KVAS.

4. [【Win Pwn】HEVD-任意地址写](https://joe1sn.eu.org/2024/02/23/win-hevd-exp-arbitrary-write/)

   [CVE-2023-21768 复现](https://joe1sn.eu.org/2024/02/23/win-hevd-exp-arbitrary-write/)

   ~~Using function hollowing as Arbitrary Write exploit.~~

   Using `NtQuerySystemInfomation` to leak EPROCESS address and system token address,  using vulnerable to read token value and write to current process to EoP. This is learned from reproduction of CVE-2023-21768.

   enhanced solution is at: 

5. [【Win Pwn】HEVD-内核栈溢出GS保护及绕过](https://joe1sn.eu.org/2024/02/24/win-hevd-exp-stackoverflow-GS/)

   Stack overflow with GS protection.

6. [【Win Pwn】Windows10 内核池溢出](https://joe1sn.eu.org/2025/04/16/win-exp-big-non-paged-pool-overflow/)

   Windows kernel Non-page pool overflow, Segment type.

   [【Win Pwn】Windows10 内核VS池溢出利用](https://joe1sn.eu.org/2026/05/01/winX-vs-pool-overflow/)

   Windows kernel Non-page pool overflow, VS type.
