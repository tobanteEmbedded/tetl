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

#ifndef TETL_BIT_BIT_CAST_HPP
#define TETL_BIT_BIT_CAST_HPP

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
/// \notes https://en.cppreference.com/w/cpp/numeric/bit_cast
///
/// \module Numeric
template <typename To, typename From>
constexpr auto bit_cast(From const& src) noexcept
    -> enable_if_t<detail::bit_castable_types<To, From>, To>
{
    // This implementation additionally requires destination type to be
    // trivially constructible
    static_assert(is_trivially_constructible_v<To>);

    To dst;
    detail::memcpy_impl<char, etl::size_t>(&dst, &src, sizeof(To));
    return dst;
}

} // namespace etl

#endif // TETL_BIT_BIT_CAST_HPP