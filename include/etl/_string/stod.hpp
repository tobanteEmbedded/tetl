// SPDX-License-Identifier: BSL-1.0
#ifndef TETL_STRING_STOD_HPP
#define TETL_STRING_STOD_HPP

#include <etl/_string/inplace_string.hpp>
#include <etl/_strings/to_floating_point.hpp>

namespace etl {

/// \brief Interprets a floating point value in a string str.
/// \param str The string to convert.
/// \param pos Pointer to integer to store the number of characters used.
/// \returns The string converted to the specified floating point type.
template <size_t Capacity>
[[nodiscard]] constexpr auto stof(inplace_string<Capacity> const& str, size_t* pos = nullptr) -> float
{
    (void)pos;
    return strings::to_floating_point<float>(str).value;
}

/// \brief Interprets a floating point value in a string str.
/// \param str The string to convert.
/// \param pos Pointer to integer to store the number of characters used.
/// \returns The string converted to the specified floating point type.
template <size_t Capacity>
[[nodiscard]] constexpr auto stod(inplace_string<Capacity> const& str, size_t* pos = nullptr) -> double
{
    (void)pos;
    return strings::to_floating_point<double>(str).value;
}

/// \brief Interprets a floating point value in a string str.
/// \param str The string to convert.
/// \param pos Pointer to integer to store the number of characters used.
/// \returns The string converted to the specified floating point type.
template <size_t Capacity>
[[nodiscard]] constexpr auto stold(inplace_string<Capacity> const& str, size_t* pos = nullptr) -> long double
{
    (void)pos;
    return strings::to_floating_point<long double>(str).value;
}

} // namespace etl

#endif // TETL_STRING_STOD_HPP
