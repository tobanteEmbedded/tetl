// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CWCHAR_WINT_T_HPP
#define TETL_CWCHAR_WINT_T_HPP

#include <etl/_config/all.hpp>

#if defined(TETL_MSVC)
    #include <wchar.h>
#else

    #if !defined(WEOF)
        #define WEOF (static_cast<wint_t>(-1))
    #endif

    #if !defined(WCHAR_MIN)
        #define WCHAR_MIN TETL_WCHAR_MIN
    #endif

    #if !defined(WCHAR_MAX)
        #define WCHAR_MAX TETL_WCHAR_MAX
    #endif

#endif

namespace etl {

#if !defined(wint_t)
using wint_t = unsigned int;
#else
using wint_t = wint_t;
#endif

} // namespace etl

#endif // TETL_CWCHAR_WINT_T_HPP
