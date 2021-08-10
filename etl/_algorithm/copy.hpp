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

#ifndef TETL_ALGORITHM_COPY_HPP
#define TETL_ALGORITHM_COPY_HPP

namespace etl {

/// \brief Copies the elements in the range, defined by `[first, last)`, to
/// another range beginning at destination.
/// \details Copies all elements in the range `[first, last)` starting from
/// first and proceeding to `last - 1`. The behavior is undefined if destination
/// is within the range `[first, last)`. In this case, copy_backward may be used
/// instead.
/// \returns Output iterator to the element in the destination range, one past
/// the last element copied.
/// \group copy
/// \module Algorithm
template <typename InputIt, typename OutputIt>
constexpr auto copy(InputIt first, InputIt last, OutputIt destination)
    -> OutputIt
{
    for (; first != last; ++first, ++destination) { *destination = *first; }
    return destination;
}

} // namespace etl

#endif // TETL_ALGORITHM_COPY_HPP