// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CONFIG_KEYWORDS_HPP
#define TETL_CONFIG_KEYWORDS_HPP

#if defined(__cpp_consteval)
    #define TETL_CONSTEVAL consteval
#else
    #define TETL_CONSTEVAL constexpr
#endif

#endif // TETL_CONFIG_KEYWORDS_HPP
