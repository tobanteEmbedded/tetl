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

#endif // TETL_CONFIG_ATTRIBUTES_HPP