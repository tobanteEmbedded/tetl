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

#ifndef TETL_ALGORITHM_LEXICOGRAPHICAL_COMPARE_HPP
#define TETL_ALGORITHM_LEXICOGRAPHICAL_COMPARE_HPP

#include "etl/_functional/less.hpp"

namespace etl {

/// \brief Checks if the first range `[f1, l1)` is lexicographically
/// less than the second range `[f2, l2)`.
///
/// \notes
/// [cppreference.com/w/cpp/algorithm/lexicographical_compare](https://en.cppreference.com/w/cpp/algorithm/lexicographical_compare)
///
/// \group lexicographical_compare
/// \module Algorithm
template <typename InputIt1, typename InputIt2, typename Compare>
[[nodiscard]] constexpr auto lexicographical_compare(
    InputIt1 f1, InputIt1 l1, InputIt2 f2, InputIt2 l2, Compare comp) -> bool
{
    for (; (f1 != l1) && (f2 != l2); ++f1, (void)++f2) {
        if (comp(*f1, *f2)) { return true; }
        if (comp(*f2, *f1)) { return false; }
    }
    return (f1 == l1) && (f2 != l2);
}

/// \group lexicographical_compare
template <typename InputIt1, typename InputIt2>
[[nodiscard]] constexpr auto lexicographical_compare(
    InputIt1 f1, InputIt1 l1, InputIt2 f2, InputIt2 l2) -> bool
{
    return lexicographical_compare(f1, l1, f2, l2, less<decltype(*f1)> {});
}

} // namespace etl

#endif // TETL_ALGORITHM_LEXICOGRAPHICAL_COMPARE_HPP