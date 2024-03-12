// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CSTDLIB_STRTOUL_HPP
#define TETL_CSTDLIB_STRTOUL_HPP

#include <etl/_cassert/macro.hpp>
#include <etl/_cstring/strlen.hpp>
#include <etl/_strings/conversion.hpp>
#include <etl/_warning/ignore_unused.hpp>

namespace etl {

/// \brief Interprets an integer value in a byte string pointed to by str.
///
/// https://en.cppreference.com/w/cpp/string/byte/strtoul
[[nodiscard]] constexpr auto strtoul(char const* str, char const** last, int base) noexcept -> unsigned long
{
    auto const len = strlen(str);
    auto const res = detail::string_to_integer<unsigned long, detail::skip_whitespace::yes>(
        str,
        len,
        static_cast<unsigned long>(base)
    );
    if (last != nullptr) {
        *last = res.end;
    }
    return res.value;
}

/// \brief Interprets an integer value in a byte string pointed to by str.
///
/// https://en.cppreference.com/w/cpp/string/byte/strtoul
[[nodiscard]] constexpr auto strtoull(char const* str, char const** last, int base) noexcept -> unsigned long long
{
    auto const len = strlen(str);
    auto const res = detail::string_to_integer<unsigned long long, detail::skip_whitespace::yes>(
        str,
        len,
        static_cast<unsigned long long>(base)
    );
    if (last != nullptr) {
        *last = res.end;
    }
    return res.value;
}

} // namespace etl

#endif // TETL_CSTDLIB_STRTOUL_HPP
