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

namespace taetl
{
/**
 * @brief The class template bitset represents a fixed-size sequence of N bits.
 * Bitsets can be manipulated by standard logic operators.
 *
 * @todo Converted to and from strings and integers. Add operators & more docs.
 */
template <taetl::size_t N>
class bitset
{
public:
    bitset();

    auto operator[](taetl::size_t bit) const -> bool;
    auto test(taetl::size_t bit) const -> bool;

    auto set(taetl::size_t bit) -> void;
    auto reset(taetl::size_t bit) -> void;
    auto flip(taetl::size_t bit) -> void;

private:
    static constexpr taetl::size_t bits_in_int = CHAR_BIT * sizeof(unsigned);
    array<unsigned, N> data_;
};

template <taetl::size_t N>
bitset<N>::bitset() : data_()
{
}

template <taetl::size_t N>
auto bitset<N>::operator[](taetl::size_t bit) const -> bool
{
    return test(bit);
}

template <taetl::size_t N>
auto bitset<N>::test(taetl::size_t bit) const -> bool
{
    return ((data_[bit / bits_in_int] & (1U << (bit % bits_in_int))) != 0);
}

template <taetl::size_t N>
void bitset<N>::set(taetl::size_t bit)
{
    data_[bit / bits_in_int] |= (1U << (bit % bits_in_int));
}

template <taetl::size_t N>
void bitset<N>::reset(taetl::size_t bit)
{
    data_[bit / bits_in_int] &= ~(1U << (bit % bits_in_int));
}

template <taetl::size_t N>
void bitset<N>::flip(taetl::size_t bit)
{
    data_[bit / bits_in_int] ^= (1U << (bit % bits_in_int));
}

}  // namespace taetl

#endif  // TAETL_BITSET_HPP