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

#ifndef TETL_ALGORITHM_TRANSFORM_HPP
#define TETL_ALGORITHM_TRANSFORM_HPP

namespace etl {

/// \brief Applies the given function to a range and stores the result in
/// another range, beginning at dest. The unary operation op is applied to
/// the range defined by `[first, last)`.
///
/// \param first The first range of elements to transform.
/// \param last The first range of elements to transform.
/// \param dest The beginning of the destination range, may be equal to first.
/// \param op Unary operation function object that will be applied.
///
/// \notes
/// [cppreference.com/w/cpp/algorithm/transform](https://en.cppreference.com/w/cpp/algorithm/transform)
///
/// \group transform
/// \module Algorithm
template <typename InputIt, typename OutputIt, typename UnaryOp>
constexpr auto transform(InputIt first, InputIt last, OutputIt dest, UnaryOp op)
    -> OutputIt
{
    for (; first != last; ++first, ++dest) { *dest = op(*first); }
    return dest;
}

/// \group transform
template <typename InputIt1, typename InputIt2, typename OutputIt,
    typename BinaryOp>
constexpr auto transform(InputIt1 first1, InputIt1 last1, InputIt2 first2,
    OutputIt dest, BinaryOp op) -> OutputIt
{
    for (; first1 != last1; ++first1, ++first2, ++dest) {
        *dest = op(*first1, *first2);
    }
    return dest;
}

} // namespace etl

#endif // TETL_ALGORITHM_TRANSFORM_HPP