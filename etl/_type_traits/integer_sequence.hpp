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

#ifndef TETL_TYPE_TRAITS_INTEGER_SEQUENCE_HPP
#define TETL_TYPE_TRAITS_INTEGER_SEQUENCE_HPP

#include "etl/_config/builtin_functions.hpp"
#include "etl/_cstddef/size_t.hpp"
#include "etl/_type_traits/is_integral.hpp"

namespace etl {

namespace detail {
template <size_t...>
struct tuple_indices {
};
} // namespace detail

/// \group integer_sequence
template <typename T, T... Ints>
struct integer_sequence {
    static_assert(is_integral_v<T>, "T must be an integral type.");

    using value_type = T;

    [[nodiscard]] static constexpr auto size() noexcept -> size_t
    {
        return sizeof...(Ints);
    }

    using to_tuple_indices = detail::tuple_indices<Ints...>;
};

/// \group integer_sequence
template <typename T, T Size>
using make_integer_sequence = TETL_BUILTIN_INT_SEQ(T, Size);

} // namespace etl

#endif // TETL_TYPE_TRAITS_INTEGER_SEQUENCE_HPP