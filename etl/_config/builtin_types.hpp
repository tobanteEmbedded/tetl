/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CONFIG_BUILTIN_TYPES_HPP
#define TETL_CONFIG_BUILTIN_TYPES_HPP

#ifdef _MSC_VER
#define TETL_BUILTIN_INT8 __int8
#define TETL_BUILTIN_INT16 __int16
#define TETL_BUILTIN_INT32 __int32
#define TETL_BUILTIN_INT64 __int64
#define TETL_BUILTIN_UINT8 unsigned __int8
#define TETL_BUILTIN_UINT16 unsigned __int16
#define TETL_BUILTIN_UINT32 unsigned __int32
#define TETL_BUILTIN_UINT64 unsigned __int64

#define TETL_BUILTIN_INTPTR TETL_BUILTIN_INT64
#define TETL_BUILTIN_UINTPTR TETL_BUILTIN_UINT64
#define TETL_BUILTIN_INTMAX TETL_BUILTIN_INT64
#define TETL_BUILTIN_UINTMAX TETL_BUILTIN_UINT64
#define TETL_BUILTIN_SIZET decltype(sizeof(nullptr))
#define TETL_BUILTIN_PTRDIFF TETL_BUILTIN_INT64
#else
#define TETL_BUILTIN_INT8 __INT8_TYPE__
#define TETL_BUILTIN_INT16 __INT16_TYPE__
#define TETL_BUILTIN_INT32 __INT32_TYPE__
#define TETL_BUILTIN_INT64 __INT64_TYPE__
#define TETL_BUILTIN_UINT8 __UINT8_TYPE__
#define TETL_BUILTIN_UINT16 __UINT16_TYPE__
#define TETL_BUILTIN_UINT32 __UINT32_TYPE__
#define TETL_BUILTIN_UINT64 __UINT64_TYPE__

#define TETL_BUILTIN_INTPTR __INTPTR_TYPE__
#define TETL_BUILTIN_UINTPTR __UINTPTR_TYPE__
#define TETL_BUILTIN_INTMAX __INTMAX_TYPE__
#define TETL_BUILTIN_UINTMAX __UINTMAX_TYPE__
#define TETL_BUILTIN_SIZET __SIZE_TYPE__
#define TETL_BUILTIN_PTRDIFF __PTRDIFF_TYPE__
#endif

#if !defined(TETL_WCHAR_MIN)
#if defined(__WCHAR_MIN__)
#define TETL_WCHAR_MIN __WCHAR_MIN__
#elif defined(__WCHAR_UNSIGNED__) || (L'\0' - 1 > 0)
#define TETL_WCHAR_MIN (0 + L'\0')
#else
#define TETL_WCHAR_MIN (-0x7fffffff - 1 + L'\0')
#endif
#endif // TETL_WCHAR_MIN

#if !defined(TETL_WCHAR_MAX)
#if defined(__WCHAR_MAX__)
#define TETL_WCHAR_MAX __WCHAR_MAX__
#elif defined(__WCHAR_UNSIGNED__) || (L'\0' - 1 > 0)
#define TETL_WCHAR_MAX (0xffffffffu + L'\0')
#else
#define TETL_WCHAR_MAX (0x7fffffff + L'\0')
#endif
#endif // TETL_WCHAR_MAX

#endif // TETL_CONFIG_BUILTIN_TYPES_HPP