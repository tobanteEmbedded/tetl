/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_BIT_BIT_CAST_HPP
#define TETL_BIT_BIT_CAST_HPP

#include "etl/_config/all.hpp"

#include "etl/_cstddef/size_t.hpp"
#include "etl/_strings/cstr_algorithm.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_trivially_constructible.hpp"
#include "etl/_type_traits/is_trivially_copyable.hpp"

namespace etl {

namespace detail {
// clang-format off
template <typename To, typename From>
inline constexpr auto bit_castable_types
    = (sizeof(To) == sizeof(From))
      && is_trivially_copyable_v<From>
      && is_trivially_copyable_v<To>;
}
// clang-format on

/// \brief Obtain a value of type To by reinterpreting the object representation
/// of from. Every bit in the value representation of the returned To object is
/// equal to the corresponding bit in the object representation of from.
///
/// \details The values of padding bits in the returned To object are
/// unspecified. If there is no value of type To corresponding to the value
/// representation produced, the behavior is undefined. If there are multiple
/// such values, which value is produced is unspecified. This overload only
/// participates in overload resolution if sizeof(To) == sizeof(From) and both
/// To and From are TriviallyCopyable types.
///
/// \details https://en.cppreference.com/w/cpp/numeric/bit_cast
///
/// \module Numeric
template <typename To, typename From, enable_if_t<detail::bit_castable_types<To, From>, int> = 0>
constexpr auto bit_cast(From const& src) noexcept -> To
{
#if __has_builtin(__builtin_bit_cast)
    return __builtin_bit_cast(To, src);
#else
    // This implementation additionally requires destination type to be
    // trivially constructible
    static_assert(is_trivially_constructible_v<To>);

    To dst {};
    detail::memcpy_impl<char, etl::size_t>(&dst, &src, sizeof(To));
    return dst;
#endif
}

} // namespace etl

#endif // TETL_BIT_BIT_CAST_HPP