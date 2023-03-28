/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#ifndef TETL_STRING_STOI_HPP
#define TETL_STRING_STOI_HPP

#include "etl/_string/static_string.hpp"
#include "etl/_strings/conversion.hpp"

namespace etl {

/// \brief Interprets a signed integer value in the string str.
/// \param str The string to convert.
/// \param pos Address of an integer to store the number of characters
/// processed.
/// \param base The number base.
/// \returns Integer value corresponding to the content of str.
template <size_t Capacity>
[[nodiscard]] constexpr auto stoi(static_string<Capacity> const& str, size_t* pos = nullptr, int base = 10) -> int
{
    ignore_unused(pos);
    auto const res = detail::ascii_to_integer<int>(str.c_str(), str.size(), base);
    return res.value;
}

/// \brief Interprets a signed integer value in the string str.
/// \param str The string to convert.
/// \param pos Address of an integer to store the number of characters
/// processed.
/// \param base The number base.
/// \returns Integer value corresponding to the content of str.
template <size_t Capacity>
[[nodiscard]] constexpr auto stol(static_string<Capacity> const& str, size_t* pos = nullptr, int base = 10) -> long
{
    ignore_unused(pos);
    auto const res = detail::ascii_to_integer<long>(str.c_str(), str.size(), base);
    return res.value;
}

/// \brief Interprets a signed integer value in the string str.
/// \param str The string to convert.
/// \param pos Address of an integer to store the number of characters
/// processed.
/// \param base The number base.
/// \returns Integer value corresponding to the content of str.
template <size_t Capacity>
[[nodiscard]] constexpr auto stoll(static_string<Capacity> const& str, size_t* pos = nullptr, int base = 10)
    -> long long
{
    ignore_unused(pos);
    auto const res = detail::ascii_to_integer<long long>(str.c_str(), str.size(), base);
    return res.value;
}

/// \brief Interprets a signed integer value in the string str.
/// \param str The string to convert.
/// \param pos Address of an integer to store the number of characters
/// processed.
/// \param base The number base.
/// \returns Integer value corresponding to the content of str.
template <size_t Capacity>
[[nodiscard]] constexpr auto stoul(static_string<Capacity> const& str, size_t* pos = nullptr, int base = 10)
    -> unsigned long
{
    ignore_unused(pos);
    auto const res = detail::ascii_to_integer<unsigned long>(str.c_str(), str.size(), base);
    return res.value;
}

/// \brief Interprets a signed integer value in the string str.
/// \param str The string to convert.
/// \param pos Address of an integer to store the number of characters
/// processed.
/// \param base The number base.
/// \returns Integer value corresponding to the content of str.
template <size_t Capacity>
[[nodiscard]] constexpr auto stoull(static_string<Capacity> const& str, size_t* pos = nullptr, int base = 10)
    -> unsigned long long
{
    ignore_unused(pos);
    auto const res = detail::ascii_to_integer<unsigned long long>(str.c_str(), str.size(), base);
    return res.value;
}

} // namespace etl

#endif // TETL_STRING_STOI_HPP
