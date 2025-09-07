// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch
#ifndef TETL_STRING_STOD_HPP
#define TETL_STRING_STOD_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_iterator/distance.hpp>
#include <etl/_string/basic_inplace_string.hpp>
#include <etl/_strings/to_floating_point.hpp>

namespace etl {

/// \brief Interprets a floating point value in a string str.
/// \param str The string to convert.
/// \param pos Pointer to integer to store the number of characters used.
/// \returns The string converted to the specified floating point type.
/// \ingroup string
template <size_t Capacity>
[[nodiscard]] constexpr auto stof(inplace_string<Capacity> const& str, size_t* pos = nullptr) -> float
{
    auto const result = etl::strings::to_floating_point<float>({str.data(), str.size()});
    if (pos != nullptr) {
        *pos = static_cast<size_t>(etl::distance(str.data(), result.end));
    }
    return result.value;
}

/// \brief Interprets a floating point value in a string str.
/// \param str The string to convert.
/// \param pos Pointer to integer to store the number of characters used.
/// \returns The string converted to the specified floating point type.
/// \ingroup string
template <size_t Capacity>
[[nodiscard]] constexpr auto stod(inplace_string<Capacity> const& str, size_t* pos = nullptr) -> double
{
    auto const result = etl::strings::to_floating_point<double>({str.data(), str.size()});
    if (pos != nullptr) {
        *pos = static_cast<size_t>(etl::distance(str.data(), result.end));
    }
    return result.value;
}

/// \brief Interprets a floating point value in a string str.
/// \param str The string to convert.
/// \param pos Pointer to integer to store the number of characters used.
/// \returns The string converted to the specified floating point type.
/// \ingroup string
template <size_t Capacity>
[[nodiscard]] constexpr auto stold(inplace_string<Capacity> const& str, size_t* pos = nullptr) -> long double
{
    auto const result = etl::strings::to_floating_point<long double>({str.data(), str.size()});
    if (pos != nullptr) {
        *pos = static_cast<size_t>(etl::distance(str.data(), result.end));
    }
    return result.value;
}

} // namespace etl

#endif // TETL_STRING_STOD_HPP
