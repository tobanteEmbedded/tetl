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

#ifndef TETL_FUNCTIONAL_MINUS_HPP
#define TETL_FUNCTIONAL_MINUS_HPP

#include "etl/_utility/forward.hpp"

namespace etl {

/// \brief Function object for performing subtraction. Effectively calls
/// operator- on two instances of type T.
/// \notes
/// [cppreference.com/w/cpp/utility/functional/minus](https://en.cppreference.com/w/cpp/utility/functional/minus)
/// \group minus
/// \module Utility
template <typename T = void>
struct minus {
    /// \brief Returns the difference between lhs and rhs.
    [[nodiscard]] constexpr auto operator()(T const& lhs, T const& rhs) const
        -> T
    {
        return lhs - rhs;
    }
};

/// \group minus
template <>
struct minus<void> {
    using is_transparent = void;

    /// \brief Returns the difference between lhs and rhs.
    template <typename T, typename U>
    [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
        -> decltype(etl::forward<T>(lhs) - etl::forward<U>(rhs))
    {
        return lhs - rhs;
    }
};

} // namespace etl

#endif // TETL_FUNCTIONAL_MINUS_HPP