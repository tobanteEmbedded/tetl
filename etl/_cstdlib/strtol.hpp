/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CSTDLIB_STRTOL_HPP
#define TETL_CSTDLIB_STRTOL_HPP

#include "etl/_cassert/macro.hpp"
#include "etl/_cstring/strlen.hpp"
#include "etl/_strings/conversion.hpp"
#include "etl/_warning/ignore_unused.hpp"

namespace etl {

/// \brief Interprets an integer value in a byte string pointed to by str.
///
/// https://en.cppreference.com/w/cpp/string/byte/strtol
[[nodiscard]] constexpr auto strtol(char const* str, char const** last, int base) noexcept -> long
{
    TETL_ASSERT(base == 10);
    etl::ignore_unused(base);

    auto const len = etl::strlen(str);
    auto const res = detail::ascii_to_int_base10<long, char>(str, len);
    if (last != nullptr) { *last = res.end; }
    return res.value;
}

/// \brief Interprets an integer value in a byte string pointed to by str.
///
/// https://en.cppreference.com/w/cpp/string/byte/strtol
[[nodiscard]] constexpr auto strtoll(char const* str, char const** last, int base) noexcept -> long long
{
    TETL_ASSERT(base == 10);
    etl::ignore_unused(base);

    auto const len = etl::strlen(str);
    auto const res = detail::ascii_to_int_base10<long long, char>(str, len);
    if (last != nullptr) { *last = res.end; }
    return res.value;
}

} // namespace etl

#endif // TETL_CSTDLIB_STRTOL_HPP