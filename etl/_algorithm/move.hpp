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

#ifndef TETL_ALGORITHM_MOVE_HPP
#define TETL_ALGORITHM_MOVE_HPP

#include "etl/_utility/move.hpp"

namespace etl {

/// \brief Moves the elements in the range `[first, last)`, to another range
/// beginning at destination, starting from first and proceeding to `last - 1`.
/// After this operation the elements in the moved-from range will still contain
/// valid values of the appropriate type, but not necessarily the same values as
/// before the move.
///
/// \param first The range of elements to move.
/// \param last The range of elements to move.
/// \param destination The beginning of the destination range.
///
/// \returns Output iterator to the element past the last element moved.
///
/// https://en.cppreference.com/w/cpp/algorithm/move
///
/// \module Algorithm
template <typename InputIt, typename OutputIt>
constexpr auto move(InputIt first, InputIt last, OutputIt destination)
    -> OutputIt
{
    for (; first != last; ++first, (void)++destination) {
        *destination = move(*first);
    }
    return destination;
}

} // namespace etl

#endif // TETL_ALGORITHM_MOVE_HPP