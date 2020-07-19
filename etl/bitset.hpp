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

#ifndef TAETL_BITSET_HPP
#define TAETL_BITSET_HPP

#include "array.hpp"
#include "definitions.hpp"

namespace etl
{
/**
 * @brief The class template bitset represents a fixed-size sequence of N bits.
 * Bitsets can be manipulated by standard logic operators.
 *
 * @todo Converted to and from strings and integers. Add operators & more docs.
 */
template <size_t NumberOfBits>
class bitset
{
public:
    constexpr bitset() noexcept = default;

    constexpr auto set(size_t const pos) -> void
    {
        bits_[pos >> 3] |= (1 << (pos & 0x7));
    }

    [[nodiscard]] constexpr auto test(size_t const pos) const -> bool
    {
        return (bits_[pos >> 3] & (1 << (pos & 0x7))) != 0;
    }

    [[nodiscard]] constexpr auto operator[](size_t const pos) const -> bool
    {
        return test(pos);
    }

private:
    static constexpr size_t size_          = NumberOfBits;
    static constexpr size_t allocated_     = NumberOfBits >> 3;
    array<unsigned char, allocated_> bits_ = {};
};

}  // namespace etl

#endif  // TAETL_BITSET_HPP