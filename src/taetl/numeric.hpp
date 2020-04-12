/*
Copyright (c) 2019-2020, Tobias Hienzsch
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
*/

#ifndef TAETL_NUMERIC_HPP
#define TAETL_NUMERIC_HPP

// TAETL
#include "definitions.hpp"

namespace taetl
{
/**
 * @brief Computes the sum of the given value init and the elements in the range
 * [first, last). Uses operator+ to sum up the elements.
 */
template <class InputIt, class Type>
constexpr Type accumulate(InputIt first, InputIt last, Type init) noexcept
{
    for (; first != last; ++first)
    {
        init = init + *first;  // std::move since C++20
    }
    return init;
}

/**
 * @brief Computes the sum of the given value init and the elements in the range
 * [first, last). Uses the BinaryOperation to sum up the elements.
 */
template <class InputIt, class Type, class BinaryOperation>
constexpr Type accumulate(InputIt first, InputIt last, Type init,
                          BinaryOperation op) noexcept
{
    for (; first != last; ++first)
    {
        init = op(init, *first);  // std::move since C++20
    }
    return init;
}

/**
 * @brief Returns the absolute value.
 */
template <typename Type>
constexpr Type abs(Type input) noexcept
{
    if (input < 0) { return input * -1; }
    return input;
}

}  // namespace taetl

#endif  // TAETL_NUMERIC_HPP