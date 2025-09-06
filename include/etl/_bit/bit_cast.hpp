// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2020 Tobias Hienzsch

#ifndef TETL_BIT_BIT_CAST_HPP
#define TETL_BIT_BIT_CAST_HPP

#include <etl/_config/all.hpp>

#include <etl/_cstddef/size_t.hpp>
#include <etl/_strings/cstr.hpp>
#include <etl/_type_traits/is_trivially_constructible.hpp>
#include <etl/_type_traits/is_trivially_copyable.hpp>

namespace etl {

namespace detail {

template <typename To, typename From>
concept bitcastable = (sizeof(To) == sizeof(From)) and is_trivially_copyable_v<From> and is_trivially_copyable_v<To>;

} // namespace detail

/// Obtain a value of type To by reinterpreting the object representation
/// of from. Every bit in the value representation of the returned To object is
/// equal to the corresponding bit in the object representation of from.
///
/// The values of padding bits in the returned To object are
/// unspecified. If there is no value of type To corresponding to the value
/// representation produced, the behavior is undefined. If there are multiple
/// such values, which value is produced is unspecified. This overload only
/// participates in overload resolution if sizeof(To) == sizeof(From) and both
/// To and From are TriviallyCopyable types.
///
/// https://en.cppreference.com/w/cpp/numeric/bit_cast
///
/// \ingroup bit
template <typename To, typename From>
    requires detail::bitcastable<To, From>
constexpr auto bit_cast(From const& src) noexcept -> To
{
#if __has_builtin(__builtin_bit_cast) or (defined(_MSC_VER) and not defined(__clang__))
    return __builtin_bit_cast(To, src);
#else
    To dst{};
    etl::detail::memcpy<char, etl::size_t>(&dst, &src, sizeof(To));
    return dst;
#endif
}

} // namespace etl

#endif // TETL_BIT_BIT_CAST_HPP
