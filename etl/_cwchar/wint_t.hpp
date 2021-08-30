/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CWCHAR_WINT_T_HPP
#define TETL_CWCHAR_WINT_T_HPP

#include "etl/_config/builtin_types.hpp"
#include "etl/_config/compiler.hpp"

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