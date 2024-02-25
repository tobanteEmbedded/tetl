// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CONFIG_ATTRIBUTES_HPP
#define TETL_CONFIG_ATTRIBUTES_HPP

#if __has_attribute(always_inline)
    #define TETL_ALWAYS_INLINE __attribute__((always_inline))
#elif defined(_MSC_VER)
    #define TETL_ALWAYS_INLINE __forceinline
#else
    #define TETL_ALWAYS_INLINE
#endif

#if __has_attribute(noinline)
    #define TETL_NO_INLINE __attribute__((noinline))
#elif defined(_MSC_VER)
    #define TETL_NO_INLINE __declspec(noinline)
#else
    #define TETL_NO_INLINE
#endif

#if __has_attribute(cold)
    #define TETL_COLD __attribute__((cold))
#else
    #define TETL_COLD
#endif

// EXPECT
#if __has_builtin(__builtin_expect)
    #define TETL_LIKELY(expr) __builtin_expect(static_cast<bool>(expr), true)
    #define TETL_UNLIKELY(expr) __builtin_expect(static_cast<bool>(expr), false)
#else
    #define TETL_LIKELY(expr) (expr)
    #define TETL_UNLIKELY(expr) (expr)
#endif

#if defined(_MSC_VER) and not defined(__clang__)
    #define TETL_NO_UNIQUE_ADDRESS [[msvc::no_unique_address]]
#elif defined(_MSC_VER) and defined(__clang__)
    // Reenable [[msvc::no_unique_address]] for clang v18
    #define TETL_NO_UNIQUE_ADDRESS
#else
    #define TETL_NO_UNIQUE_ADDRESS [[no_unique_address]]
#endif

#endif // TETL_CONFIG_ATTRIBUTES_HPP
