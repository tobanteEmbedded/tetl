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

#ifndef TETL_DETAIL_FUNCTIONAL_BIT_XOR_HPP
#define TETL_DETAIL_FUNCTIONAL_BIT_XOR_HPP

#include "etl/_utility/forward.hpp"

namespace etl {

/// \brief Function object for performing bitwise XOR. Effectively calls
/// operator^ on type T.
/// \notes
/// [cppreference.com/w/cpp/utility/functional/bit_xor](https://en.cppreference.com/w/cpp/utility/functional/bit_xor)
/// \group bit_xor
/// \module Utility
template <typename T = void>
struct bit_xor {
    [[nodiscard]] constexpr auto operator()(T const& lhs, T const& rhs) const
        -> T
    {
        return lhs ^ rhs;
    }
};

/// \group bit_xor
template <>
struct bit_xor<void> {
    using is_transparent = void;

    template <typename T, typename U>
    [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
        -> decltype(etl::forward<T>(lhs) ^ etl::forward<U>(rhs))
    {
        return lhs ^ rhs;
    }
};

} // namespace etl

#endif // TETL_DETAIL_FUNCTIONAL_BIT_XOR_HPP