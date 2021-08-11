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
#ifndef TETL_NUMERIC_INNER_PRODUCT_HPP
#define TETL_NUMERIC_INNER_PRODUCT_HPP

#include "etl/_utility/move.hpp"

namespace etl {

/// \brief Computes inner product (i.e. sum of products) or performs ordered
/// map/reduce operation on the range [first1, last1) and the range beginning at
/// first2.
/// \group inner_product
/// \module Algorithm
template <typename InputIt1, typename InputIt2, typename T>
[[nodiscard]] constexpr auto inner_product(
    InputIt1 first1, InputIt1 last1, InputIt2 first2, T init) -> T
{
    for (; first1 != last1; ++first1, ++first2) {
        init = etl::move(init) + *first1 * *first2;
    }
    return init;
}

/// \group inner_product
template <typename InputIt1, typename InputIt2, typename T,
    typename BinaryOperation1, typename BinaryOperation2>
[[nodiscard]] constexpr auto inner_product(InputIt1 first1, InputIt1 last1,
    InputIt2 first2, T init, BinaryOperation1 op1, BinaryOperation2 op2) -> T
{
    for (; first1 != last1; ++first1, ++first2) {
        init = op1(etl::move(init), op2(*first1, *first2));
    }
    return init;
}

} // namespace etl

#endif // TETL_NUMERIC_INNER_PRODUCT_HPP