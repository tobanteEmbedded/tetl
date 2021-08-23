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
#ifndef TETL_NUMERIC_REDUCE_HPP
#define TETL_NUMERIC_REDUCE_HPP

#include "etl/_functional/plus.hpp"
#include "etl/_iterator/iterator_traits.hpp"
#include "etl/_numeric/accumulate.hpp"
#include "etl/_utility/move.hpp"

namespace etl {

/// \brief Similar to etl::accumulate.
/// https://en.cppreference.com/w/cpp/algorithm/reduce
/// \group reduce
/// \module Algorithm
template <typename InputIter, typename T, typename BinaryOp>
[[nodiscard]] constexpr auto reduce(
    InputIter first, InputIter last, T init, BinaryOp op) -> T
{
    return accumulate(first, last, init, op);
}

/// \group reduce
template <typename InputIter, typename T>
[[nodiscard]] constexpr auto reduce(InputIter first, InputIter last, T init)
    -> T
{
    return reduce(first, last, init, etl::plus<>());
}

/// \group reduce
template <typename InputIter>
[[nodiscard]] constexpr auto reduce(InputIter first, InputIter last) ->
    typename etl::iterator_traits<InputIter>::value_type
{
    auto init = typename etl::iterator_traits<InputIter>::value_type {};
    return reduce(first, last, init);
}

} // namespace etl

#endif // TETL_NUMERIC_REDUCE_HPP