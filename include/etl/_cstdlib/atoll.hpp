/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CSTDLIB_ATOLL_HPP
#define TETL_CSTDLIB_ATOLL_HPP

#include <etl/_cstring/strlen.hpp>
#include <etl/_strings/conversion.hpp>

namespace etl {

/// \brief Interprets an integer value in a byte string pointed to by str.
/// Discards any whitespace characters until the first non-whitespace character
/// is found, then takes as many characters as possible to form a valid integer
/// number representation and converts them to an integer value.
[[nodiscard]] constexpr auto atoll(char const* string) noexcept -> long long
{
    auto const result = detail::ascii_to_integer<long long, char, true>(string, strlen(string));
    return result.value;
}

} // namespace etl

#endif // TETL_CSTDLIB_ATOLL_HPP
