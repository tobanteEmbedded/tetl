// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.
#ifndef TETL_STRING_TO_STRING_HPP
#define TETL_STRING_TO_STRING_HPP

#include "etl/_string/static_string.hpp"
#include "etl/_strings/conversion.hpp"

namespace etl {

namespace detail {
template <size_t Capacity, typename Int>
auto to_string_impl(Int val) -> static_string<Capacity>
{
    char buffer[Capacity] {};
    auto* first    = ::etl::begin(buffer);
    auto const res = detail::int_to_ascii<Int>(val, first, 10, Capacity);
    if (res.error == detail::int_to_ascii_error::none) {
        return static_string<Capacity> { first, res.end };
    }
    return {};
}
} // namespace detail

/// \brief Converts a numeric value to etl::static_string.
template <size_t Capacity>
[[nodiscard]] constexpr auto to_string(int value) noexcept
    -> static_string<Capacity>
{
    return detail::to_string_impl<Capacity, int>(value);
}

/// \brief Converts a numeric value to etl::static_string.
template <size_t Capacity>
[[nodiscard]] constexpr auto to_string(long value) noexcept
    -> static_string<Capacity>
{
    return detail::to_string_impl<Capacity, long>(value);
}

/// \brief Converts a numeric value to etl::static_string.
template <size_t Capacity>
[[nodiscard]] constexpr auto to_string(long long value) noexcept
    -> static_string<Capacity>
{
    return detail::to_string_impl<Capacity, long long>(value);
}

/// \brief Converts a numeric value to etl::static_string.
template <size_t Capacity>
[[nodiscard]] constexpr auto to_string(unsigned value) noexcept
    -> static_string<Capacity>
{
    return detail::to_string_impl<Capacity, unsigned>(value);
}

/// \brief Converts a numeric value to etl::static_string.
template <size_t Capacity>
[[nodiscard]] constexpr auto to_string(unsigned long value) noexcept
    -> static_string<Capacity>
{
    return detail::to_string_impl<Capacity, unsigned long>(value);
}

/// \brief Converts a numeric value to etl::static_string.
template <size_t Capacity>
[[nodiscard]] constexpr auto to_string(unsigned long long value) noexcept
    -> static_string<Capacity>
{
    return detail::to_string_impl<Capacity, unsigned long long>(value);
}

/// \brief Converts a numeric value to etl::static_string.
template <size_t Capacity>
[[nodiscard]] constexpr auto to_string(float value) noexcept
    -> static_string<Capacity>
{
    TETL_ASSERT(false);
    ignore_unused(value);
    return {};
}

/// \brief Converts a numeric value to etl::static_string.
template <size_t Capacity>
[[nodiscard]] constexpr auto to_string(double value) noexcept
    -> static_string<Capacity>
{
    TETL_ASSERT(false);
    ignore_unused(value);
    return {};
}

/// \brief Converts a numeric value to etl::static_string.
template <size_t Capacity>
[[nodiscard]] constexpr auto to_string(long double value) noexcept
    -> static_string<Capacity>
{
    TETL_ASSERT(false);
    ignore_unused(value);
    return {};
}

} // namespace etl

#endif // TETL_STRING_TO_STRING_HPP