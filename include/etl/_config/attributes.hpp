// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CONFIG_ATTRIBUTES_HPP
#define TETL_CONFIG_ATTRIBUTES_HPP

#if __has_attribute(always_inline)
    #define TETL_ALWAYS_INLINE [[gnu::always_inline]]
#elif defined(_MSC_VER)
    #define TETL_ALWAYS_INLINE [[msvc::forceinline]]
#else
    #define TETL_ALWAYS_INLINE
#endif

#if __has_attribute(noinline)
    #define TETL_NO_INLINE [[gnu::noinline]]
#elif defined(_MSC_VER)
    #define TETL_NO_INLINE [[msvc::noinline]]
#else
    #define TETL_NO_INLINE
#endif

#if __has_attribute(cold)
    #define TETL_COLD [[gnu::cold]]
#else
    #define TETL_COLD
#endif

#if defined(__GNUC__) or defined(__clang__)
    #define TETL_MAY_ALIAS [[gnu::may_alias]]
#else
    #define TETL_MAY_ALIAS
#endif

#if defined(_MSC_VER) and not defined(__clang__)
    #define TETL_NO_UNIQUE_ADDRESS [[msvc::no_unique_address]]
#elif defined(_MSC_VER) and defined(__clang__) and (__clang_major__ >= 18)
    #define TETL_NO_UNIQUE_ADDRESS [[msvc::no_unique_address]]
#elif defined(_MSC_VER) and defined(__clang__)
    #define TETL_NO_UNIQUE_ADDRESS
#else
    #define TETL_NO_UNIQUE_ADDRESS [[no_unique_address]]
#endif

#if defined(__clang__)
    #define TETL_TRIVIAL_ABI [[clang::trivial_abi]]
#else
    #define TETL_TRIVIAL_ABI
#endif

#endif // TETL_CONFIG_ATTRIBUTES_HPP
