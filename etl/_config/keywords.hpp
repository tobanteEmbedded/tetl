/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CONFIG_KEYWORDS_HPP
#define TETL_CONFIG_KEYWORDS_HPP

#if defined(__cpp_consteval)
#define TETL_CONSTEVAL consteval
#else
#define TETL_CONSTEVAL constexpr
#endif

#endif // TETL_CONFIG_KEYWORDS_HPP