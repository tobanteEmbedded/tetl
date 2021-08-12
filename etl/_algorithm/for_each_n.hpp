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

#ifndef TETL_ALGORITHM_FOR_EACH_N_HPP
#define TETL_ALGORITHM_FOR_EACH_N_HPP

namespace etl {

/// \brief Applies the given function object f to the result of dereferencing
/// every iterator in the range `[first, first + n]` in order.
///
/// \param first The beginning of the range to apply the function to.
/// \param n The number of elements to apply the function to.
/// \param f Function object, to be applied to the result of dereferencing every
/// iterator in the range.
///
/// \complexity Exactly n applications of f.
///
/// \notes
/// [cppreference.com/w/cpp/algorithm/for_each_n](https://en.cppreference.com/w/cpp/algorithm/for_each_n)
///
/// \module Algorithm
template <typename InputIt, typename Size, typename UnaryFunc>
constexpr auto for_each_n(InputIt first, Size n, UnaryFunc f) noexcept
    -> InputIt
{
    for (Size i = 0; i < n; ++first, (void)++i) { f(*first); }
    return first;
}

} // namespace etl

#endif // TETL_ALGORITHM_FOR_EACH_N_HPP