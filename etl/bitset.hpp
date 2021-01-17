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

/**
 * @file bitset.hpp
 * @example bitset.cpp
 */

#include "array.hpp"
#include "definitions.hpp"
#include "limits.hpp"

namespace etl
{
/**
 * @brief The class template bitset represents a fixed-size sequence of N bits.
 * Bitsets can be manipulated by standard logic operators.
 *
 * @include bitset.cpp
 * @todo Converted to and from strings and integers. Add operators & more docs.
 */
template <size_t N>
class bitset
{
public:
    /**
     * @brief The primary use of std::bitset::reference is to provide an l-value that can
     * be returned from operator[].
     *
     * @details This class is used as a proxy object to allow users to interact with
     * individual bits of a bitset, since standard C++ types (like references and
     * pointers) are not built with enough precision to specify individual bits.
     */
    class reference
    {
    public:
        /**
         * @brief Assigns a value to the referenced bit.
         */
        constexpr auto operator=(bool value) noexcept -> reference&
        {
            if (value) { *data_ |= static_cast<uint8_t>(1 << (position_)); }
            return *this;
        }

        /**
         * @brief Assigns a value to the referenced bit.
         * @returns *this
         */
        constexpr auto operator=(reference const& x) noexcept -> reference&
        {
            (*this) = static_cast<bool>(x);
            return *this;
        }

        /**
         * @brief Returns the value of the referenced bit.
         */
        [[nodiscard]] constexpr operator bool() const noexcept
        {
            return (*data_ & (1 << position_)) != 0;
        }

        /**
         * @brief Returns the inverse of the referenced bit.
         */
        [[nodiscard]] constexpr auto operator~() const noexcept -> bool
        {
            return !static_cast<bool>(*this);
        }

        /**
         * @brief Inverts the referenced bit.
         * @returns *this
         */
        constexpr auto flip() noexcept -> reference&;

    private:
        constexpr explicit reference(uint8_t* data, uint8_t position)
            : data_ {data}, position_ {position}
        {
        }

        friend bitset;
        uint8_t* data_;
        uint8_t position_;
    };

    /**
     * @brief Default constructor. Constructs a bitset with all bits set to zero.
     */
    constexpr bitset() noexcept = default;

    /**
     * @brief Constructs a bitset, initializing the first (rightmost, least
     * significant) M bit positions to the corresponding bit values of val, where M is
     * the smaller of the number of bits in an unsigned long long and the number of
     * bits N in the bitset being constructed. If M is less than N the bitset is
     * longer than 64 bits, the remaining bit positions are initialized to zeroes.
     */
    constexpr bitset(unsigned long long /*val*/) noexcept : bitset {} { }

    /**
     * @brief Sets all bits to true or to specified value. Sets all bits to true.
     */
    constexpr auto set() noexcept -> bitset<N>&
    {
        for (auto& b : bits_) { b = etl::numeric_limits<unsigned char>::max(); }
        return *this;
    }

    /**
     * @brief Sets all bits to true or to specified value. Sets the bit at position
     * pos to the value value.
     */
    constexpr auto set(etl::size_t pos, bool value = true) -> bitset<N>&
    {
        if (value) { bits_[pos >> 3] |= static_cast<uint8_t>(1 << (pos & 0x7)); }
        return *this;
    }

    /**
     * @brief Returns the value of the bit at the position pos. Perfoms no bounds
     * checking.
     */
    [[nodiscard]] constexpr auto operator[](size_t const pos) -> reference
    {
        return reference(&bits_[pos >> 3], static_cast<uint8_t>(pos & 0x7));
    }

    /**
     * @brief Returns the value of the bit at the position pos. Perfoms no bounds
     * checking.
     */
    [[nodiscard]] constexpr auto operator[](size_t const pos) const -> bool
    {
        return test(pos);
    }

    /**
     * @brief Returns the value of the bit at the position pos. Perfoms no bounds
     * checking.
     */
    [[nodiscard]] constexpr auto test(size_t const pos) const -> bool
    {
        return (bits_[pos >> 3] & (1 << (pos & 0x7))) != 0;
    }

    /**
     * @brief Checks if all bits are set to true.
     */
    [[nodiscard]] constexpr auto all() const noexcept -> bool
    {
        return count() == size();
    }

    /**
     * @brief Checks if any bits are set to true.
     */
    [[nodiscard]] constexpr auto any() const noexcept -> bool { return count() > 0; }

    /**
     * @brief Checks if none bits are set to true.
     */
    [[nodiscard]] constexpr auto none() const noexcept -> bool { return count() == 0; }

    /**
     * @brief Returns the number of bits that are set to true.
     */
    [[nodiscard]] constexpr auto count() const noexcept -> size_t
    {
        size_t count = 0;
        for (size_t i = 0; i < size(); ++i) { count += test(i) ? size_t {1} : 0; }
        return count;
    }

    /**
     * @brief Returns the number of bits that the bitset holds.
     */
    [[nodiscard]] constexpr auto size() const noexcept -> size_t { return N; }

private:
    static constexpr size_t size_      = N;
    static constexpr size_t allocated_ = N >> 3;
    array<uint8_t, allocated_> bits_   = {};
};

}  // namespace etl

#endif  // TAETL_BITSET_HPP