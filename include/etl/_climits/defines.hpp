// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_CLIMITS_DEFINES_HPP
#define TETL_CLIMITS_DEFINES_HPP

#if __has_include(<limits.h>)
    #include <limits.h>
#else

    #ifndef MB_LEN_MAX
        #define MB_LEN_MAX 1
    #endif

    #define CHAR_BIT __CHAR_BIT__

    #ifdef __CHAR_UNSIGNED__
        #define CHAR_MIN 0
        #define CHAR_MAX UCHAR_MAX
    #else
        #define CHAR_MIN SCHAR_MIN
        #define CHAR_MAX __SCHAR_MAX__
    #endif

    #define SCHAR_MAX __SCHAR_MAX__
    #define SHRT_MAX  __SHRT_MAX__
    #define INT_MAX   __INT_MAX__
    #define LONG_MAX  __LONG_MAX__

    #define SCHAR_MIN (-__SCHAR_MAX__ - 1)
    #define SHRT_MIN  (-__SHRT_MAX__ - 1)
    #define INT_MIN   (-__INT_MAX__ - 1)
    #define LONG_MIN  (-__LONG_MAX__ - 1L)

    #define UCHAR_MAX (static_cast<unsigned char>(__SCHAR_MAX__) * 2 + 1)
    #define USHRT_MAX (static_cast<unsigned short>(__SHRT_MAX__) * 2 + 1)
    #define UINT_MAX  (__INT_MAX__ * 2U + 1U)
    #define ULONG_MAX (__LONG_MAX__ * 2UL + 1UL)

    #if __STDC_VERSION__ >= 199901L || __cplusplus >= 201103L
        #undef LLONG_MIN
        #undef LLONG_MAX
        #undef ULLONG_MAX
        #define LLONG_MAX  __LONG_LONG_MAX__
        #define LLONG_MIN  (-__LONG_LONG_MAX__ - 1LL)
        #define ULLONG_MAX (__LONG_LONG_MAX__ * 2ULL + 1ULL)
    #endif

#endif // has_include <limits.h>

#endif // TETL_CLIMITS_DEFINES_HPP
