/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CSTDLIB_STRTOUL_HPP
#define TETL_CSTDLIB_STRTOUL_HPP

#include "etl/_cassert/macro.hpp"
#include "etl/_cstring/strlen.hpp"
#include "etl/_strings/conversion.hpp"
#include "etl/_warning/ignore_unused.hpp"

namespace etl {

/// \brief Interprets an integer value in a byte string pointed to by str.
///
/// https://en.cppreference.com/w/cpp/string/byte/strtoul
[[nodiscard]] constexpr auto strtoul(const char* str, char const** last, int base) noexcept -> unsigned long
{
    TETL_ASSERT(base == 10);
    etl::ignore_unused(base);

    auto const len = etl::strlen(str);
    auto const res = detail::ascii_to_int_base10<unsigned long, char>(str, len);
    if (last != nullptr) { *last = res.end; }
    return res.value;
}

/// \brief Interprets an integer value in a byte string pointed to by str.
///
/// https://en.cppreference.com/w/cpp/string/byte/strtoul
[[nodiscard]] constexpr auto strtoull(const char* str, char const** last, int base) noexcept -> unsigned long long
{
    TETL_ASSERT(base == 10);
    etl::ignore_unused(base);

    auto const len = etl::strlen(str);
    auto const res = detail::ascii_to_int_base10<unsigned long long, char>(str, len);
    if (last != nullptr) { *last = res.end; }
    return res.value;
}

} // namespace etl

#endif // TETL_CSTDLIB_STRTOUL_HPP