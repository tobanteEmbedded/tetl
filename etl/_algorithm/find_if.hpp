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

#ifndef TETL_ALGORITHM_FIND_IF_HPP
#define TETL_ALGORITHM_FIND_IF_HPP

namespace etl {

/// \brief Searches for an element for which predicate p returns true
///
/// \param first The range of elements to examine.
/// \param last The range of elements to examine.
/// \param pred Unary predicate which returns ​true for the required element.
///
/// \notes
/// [cppreference.com/w/cpp/algorithm/find](https://en.cppreference.com/w/cpp/algorithm/find)
///
/// \group find_if
/// \module Algorithm
template <typename InputIt, typename Predicate>
[[nodiscard]] constexpr auto find_if(
    InputIt first, InputIt last, Predicate pred) noexcept -> InputIt
{
    for (; first != last; ++first) {
        if (pred(*first)) { return first; }
    }
    return last;
}

} // namespace etl

#endif // TETL_ALGORITHM_FIND_IF_HPP