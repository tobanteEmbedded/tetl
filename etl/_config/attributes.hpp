/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

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

#endif // TETL_CONFIG_ATTRIBUTES_HPP