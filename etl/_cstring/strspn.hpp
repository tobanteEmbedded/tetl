/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CSTRING_STRSPN_HPP
#define TETL_CSTRING_STRSPN_HPP

#include "etl/_cstddef/size_t.hpp"
#include "etl/_strings/cstr_algorithm.hpp"

namespace etl {

/// \brief Returns the length of the maximum initial segment (span) of the byte
/// string pointed to by dest, that consists of only the characters found in
/// byte string pointed to by src.
///
/// https://en.cppreference.com/w/cpp/string/byte/strspn
///
/// \module Strings
[[nodiscard]] constexpr auto strspn(char const* dest, char const* src) noexcept -> etl::size_t
{
    return detail::str_span_impl<char, etl::size_t, true>(dest, src);
}

} // namespace etl

#endif // TETL_CSTRING_STRSPN_HPP