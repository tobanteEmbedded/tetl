// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch
#ifndef TETL_STRING_STOI_HPP
#define TETL_STRING_STOI_HPP

#include <etl/_concepts/integral.hpp>
#include <etl/_string_view/basic_string_view.hpp>
#include <etl/_strings/to_integer.hpp>

namespace etl {

namespace detail {

template <etl::integral Int>
[[nodiscard]] constexpr auto sto_impl(etl::string_view str, etl::size_t* pos, int base) -> Int
{
    auto const res = strings::to_integer<Int>(str, static_cast<Int>(base));
    if (pos != nullptr) {
        *pos = static_cast<etl::size_t>(etl::distance(str.data(), res.end));
    }
    return res.value;
}

} // namespace detail

/// \brief Interprets a signed integer value in the string str.
/// \param str The string to convert.
/// \param pos Address of an integer to store the number of characters
/// processed.
/// \param base The number base.
/// \returns Integer value corresponding to the content of str.
[[nodiscard]] constexpr auto stoi(etl::string_view str, etl::size_t* pos = nullptr, int base = 10) -> int
{
    return detail::sto_impl<int>(str, pos, base);
}

/// \brief Interprets a signed integer value in the string str.
/// \param str The string to convert.
/// \param pos Address of an integer to store the number of characters
/// processed.
/// \param base The number base.
/// \returns Integer value corresponding to the content of str.
[[nodiscard]] constexpr auto stol(etl::string_view str, etl::size_t* pos = nullptr, int base = 10) -> long
{
    return detail::sto_impl<long>(str, pos, base);
}

/// \brief Interprets a signed integer value in the string str.
/// \param str The string to convert.
/// \param pos Address of an integer to store the number of characters
/// processed.
/// \param base The number base.
/// \returns Integer value corresponding to the content of str.
[[nodiscard]] constexpr auto stoll(etl::string_view str, etl::size_t* pos = nullptr, int base = 10) -> long long
{
    return detail::sto_impl<long long>(str, pos, base);
}

/// \brief Interprets a signed integer value in the string str.
/// \param str The string to convert.
/// \param pos Address of an integer to store the number of characters
/// processed.
/// \param base The number base.
/// \returns Integer value corresponding to the content of str.
[[nodiscard]] constexpr auto stoul(etl::string_view str, etl::size_t* pos = nullptr, int base = 10) -> unsigned long
{
    return detail::sto_impl<unsigned long>(str, pos, base);
}

/// \brief Interprets a signed integer value in the string str.
/// \param str The string to convert.
/// \param pos Address of an integer to store the number of characters
/// processed.
/// \param base The number base.
/// \returns Integer value corresponding to the content of str.
[[nodiscard]] constexpr auto stoull(etl::string_view str, etl::size_t* pos = nullptr, int base = 10)
    -> unsigned long long
{
    return detail::sto_impl<unsigned long long>(str, pos, base);
}

} // namespace etl

#endif // TETL_STRING_STOI_HPP
