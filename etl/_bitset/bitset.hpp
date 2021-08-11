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

#ifndef TETL_BITSET_BITSET_HPP
#define TETL_BITSET_BITSET_HPP

#include "etl/_algorithm/min.hpp"
#include "etl/_array/array.hpp"
#include "etl/_cstddef/size_t.hpp"
#include "etl/_cstdint/uint_t.hpp"
#include "etl/_limits/numeric_limits.hpp"
#include "etl/_string_view/string_view.hpp"

namespace etl {
/// \brief The class template bitset represents a fixed-size sequence of N bits.
/// Bitsets can be manipulated by standard logic operators.
/// \module Utility
/// \todo Converted to and from strings and integers. Add operators & more docs.
/// \todo Add tests for sizes that are not a power of two. Broken at the moment.
/// \todo What if position index is out of bounds? Return nullptr?
template <etl::size_t N>
struct bitset {
    /// \brief The primary use of etl::bitset::reference is to provide an
    /// l-value that can be returned from operator[].
    ///
    /// \details This class is used as a proxy object to allow users to interact
    /// with individual bits of a bitset, since standard C++ types (like
    /// references and pointers) are not built with enough precision to specify
    /// individual bits.
    struct reference {
        /// \brief Assigns a value to the referenced bit.
        constexpr auto operator=(bool value) noexcept -> reference&
        {
            if (value) {
                *data_ |= (1U << position_);
                return *this;
            }

            *data_ &= ~(1U << position_);
            return *this;
        }

        /// \brief Assigns a value to the referenced bit.
        /// \returns *this
        constexpr auto operator=(reference const& x) noexcept -> reference&
        {
            (*this) = static_cast<bool>(x);
            return *this;
        }

        /// \brief Returns the value of the referenced bit.
        [[nodiscard]] constexpr operator bool() const noexcept
        {
            return (*data_ & (1 << position_)) != 0;
        }

        /// \brief Returns the inverse of the referenced bit.
        [[nodiscard]] constexpr auto operator~() const noexcept -> bool
        {
            return !static_cast<bool>(*this);
        }

        /// \brief Inverts the referenced bit.
        /// \returns *this
        constexpr auto flip() noexcept -> reference&
        {
            *data_ ^= 1U << position_;
            return *this;
        }

    private:
        constexpr explicit reference(uint8_t* data, uint8_t position)
            : data_ { data }, position_ { position }
        {
        }

        friend bitset;
        uint8_t* data_;
        uint8_t position_;
    };

    /// \brief Constructs a bitset with all bits set to zero.
    constexpr bitset() noexcept = default;

    /// \brief Constructs a bitset, initializing the first (rightmost, least
    /// significant) M bit positions to the corresponding bit values of val,
    /// where M is the smaller of the number of bits in an unsigned long long
    /// and the number of bits N in the bitset being constructed. If M is less
    /// than N (the bitset is longer than 64 bits, for typical implementations
    /// of unsigned long long), the remaining bit positions are initialized to
    /// zeroes.
    constexpr bitset(unsigned long long val) noexcept
    {
        auto const n
            = min<size_t>(numeric_limits<decltype(val)>::digits, size());
        for (size_t i = 0; i < n; ++i) {
            if (((val >> i) & 1U) == 1U) { set(i); }
        }
    }

    /// \brief Constructs a bitset using the characters in the
    /// etl::basic_string_view str.
    ///
    /// \details An optional starting position pos and length n can be provided,
    /// as well as characters denoting alternate values for set (one) and unset
    /// (zero) bits. Traits::eq() is used to compare the character values. The
    /// effective length of the initializing string is min(n, str.size() - pos).
    ///
    /// \param str string used to initialize the bitset
    /// \param pos a starting offset into str
    /// \param n number of characters to use from str
    /// \param zero alternate character for set bits in str
    /// \param one alternate character for unset bits in str
    template <typename CharT, typename Traits>
    explicit bitset(basic_string_view<CharT, Traits> const& str,
        typename basic_string_view<CharT, Traits>::size_type pos = 0,
        typename basic_string_view<CharT, Traits>::size_type n
        = basic_string_view<CharT, Traits>::npos,
        CharT zero = CharT('0'), CharT one = CharT('1'))
        : bitset(0ULL)
    {
        auto const len = min<decltype(pos)>(n, str.size() - pos);
        TETL_ASSERT(len >= 0);
        TETL_ASSERT(len <= size());

        for (decltype(pos) i = 0; i < len; ++i) {
            if (Traits::eq(str[i + pos], one)) { set(i, true); }
            if (Traits::eq(str[i + pos], zero)) { set(i, false); }
        }
    }

    /// \brief Constructs a bitset using the characters in the char const* str.
    ///
    /// \param str string used to initialize the bitset
    /// \param n number of characters to use from str
    /// \param zero alternate character for set bits in str
    /// \param one alternate character for unset bits in str
    template <typename CharT>
    explicit bitset(CharT const* str,
        typename basic_string_view<CharT>::size_type n
        = basic_string_view<CharT>::npos,
        CharT zero = CharT('0'), CharT one = CharT('1'))
        : bitset(n == basic_string_view<CharT>::npos
                     ? basic_string_view<CharT>(str)
                     : basic_string_view<CharT>(str, n),
            0, n, zero, one)
    {
    }

    /// \brief Sets all bits to true.
    constexpr auto set() noexcept -> bitset<N>&
    {
        for (auto& b : bits_) { b = etl::numeric_limits<uint8_t>::max(); }
        return *this;
    }

    /// \brief Sets the bit at the given position to the given value.
    ///
    /// \param pos Index of the bit to be modified.
    /// \param value The new value for the bit.
    /// \returns *this
    constexpr auto set(etl::size_t pos, bool value = true) -> bitset<N>&
    {
        if (value) {
            auto& byte  = byte_for_position(pos);
            auto offset = offset_in_byte(pos);
            byte |= (1 << offset);
            return *this;
        }

        reset(pos);
        return *this;
    }

    /// \brief Sets all bits to false.
    constexpr auto reset() noexcept -> bitset<N>&
    {
        bits_.fill(0);
        return *this;
    }

    /// \brief Sets the bit at position pos to false.
    ///
    /// \param pos Index of the bit to be reset.
    /// \returns *this
    constexpr auto reset(size_t pos) noexcept -> bitset<N>&
    {
        auto& byte  = byte_for_position(pos);
        auto offset = offset_in_byte(pos);
        byte &= ~(1U << offset);
        return *this;
    }

    /// \brief Flips all bits (like operator~, but in-place).
    constexpr auto flip() noexcept -> bitset<N>&
    {
        for (auto& b : bits_) { b = ~b; }
        return *this;
    }

    /// \brief Flips the bit at the position pos.
    ///
    /// \param pos Index of the bit to be reset.
    /// \returns *this
    constexpr auto flip(size_t pos) noexcept -> bitset<N>&
    {
        auto& byte  = byte_for_position(pos);
        auto offset = offset_in_byte(pos);
        byte ^= 1U << offset;
        return *this;
    }

    /// \brief Returns a reference like proxy to the bit at the position pos.
    /// Perfoms no bounds checking.
    ///
    /// \param pos Index of the bit.
    [[nodiscard]] constexpr auto operator[](size_t const pos) -> reference
    {
        auto& byte  = byte_for_position(pos);
        auto offset = offset_in_byte(pos);
        return reference(&byte, offset);
    }

    /// \brief Returns the value of the bit at the position pos. Perfoms no
    /// bounds checking.
    ///
    /// \param pos Index of the bit.
    [[nodiscard]] constexpr auto operator[](size_t const pos) const -> bool
    {
        return test(pos);
    }

    /// \brief Returns the value of the bit at the position pos. Perfoms no
    /// bounds checking.
    ///
    /// \param pos Index of the bit.
    [[nodiscard]] constexpr auto test(size_t const pos) const -> bool
    {
        auto& byte  = byte_for_position(pos);
        auto offset = offset_in_byte(pos);
        return (byte & (1U << offset)) != 0;
    }

    /// \brief Checks if all bits are set to true.
    [[nodiscard]] constexpr auto all() const noexcept -> bool
    {
        return count() == size();
    }

    /// \brief Checks if any bits are set to true.
    [[nodiscard]] constexpr auto any() const noexcept -> bool
    {
        return count() > 0;
    }

    /// \brief Checks if none bits are set to true.
    [[nodiscard]] constexpr auto none() const noexcept -> bool
    {
        return count() == 0;
    }

    /// \brief Returns the number of bits that are set to true.
    [[nodiscard]] constexpr auto count() const noexcept -> size_t
    {
        size_t count = 0;
        for (size_t i = 0; i < size(); ++i) {
            count += test(i) ? size_t { 1 } : 0;
        }
        return count;
    }

    /// \brief Returns the number of bits that the bitset holds.
    [[nodiscard]] constexpr auto size() const noexcept -> size_t { return N; }

    /// \brief Returns true if all of the bits in *this and rhs are equal.
    [[nodiscard]] constexpr auto operator==(bitset<N> const& rhs) const noexcept
        -> bool
    {
        for (size_t i = 0; i < size(); ++i) {
            if (test(i) != rhs.test(i)) { return false; }
        }

        return true;
    }

    /// \brief Returns true if all of the bits in *this and rhs are not equal.
    [[nodiscard]] constexpr auto operator!=(bitset<N> const& rhs) const noexcept
        -> bool
    {
        return !(*this == rhs);
    }

    /// \brief Sets the bits to the result of binary AND on corresponding pairs
    /// of bits of *this and other.
    constexpr auto operator&=(bitset<N> const& other) noexcept -> bitset<N>&
    {
        for (size_t i = 0; i < (size() >> 3); ++i) {
            bits_[i] &= other.bits_[i];
        }
        return *this;
    }

    /// \brief Sets the bits to the result of binary OR on corresponding pairs
    /// of bits of *this and other.
    constexpr auto operator|=(bitset<N> const& other) noexcept -> bitset<N>&
    {
        for (size_t i = 0; i < (size() >> 3); ++i) {
            bits_[i] |= other.bits_[i];
        }
        return *this;
    }

    /// \brief Sets the bits to the result of binary XOR on corresponding pairs
    /// of bits of *this and other.
    constexpr auto operator^=(bitset<N> const& other) noexcept -> bitset<N>&
    {
        for (size_t i = 0; i < (size() >> 3); ++i) {
            bits_[i] ^= other.bits_[i];
        }
        return *this;
    }

    /// \brief Returns a temporary copy of *this with all bits flipped (binary
    /// NOT).
    constexpr auto operator~() const noexcept -> bitset<N>
    {
        return bitset<N>(*this).flip();
    }

private:
    [[nodiscard]] constexpr auto byte_for_position(size_t pos) const
        -> uint8_t const&
    {
        TETL_ASSERT(pos < size());
        return bits_[pos >> 3];
    }

    [[nodiscard]] constexpr auto byte_for_position(size_t pos) -> uint8_t&
    {
        TETL_ASSERT(pos < size());
        return bits_[pos >> 3];
    }

    [[nodiscard]] constexpr auto offset_in_byte(size_t pos) const noexcept
        -> uint8_t
    {
        return pos & 0x7;
    }

    static constexpr size_t allocated_ = N >> 3;
    array<uint8_t, allocated_> bits_   = {};
};

} // namespace etl

#endif // TETL_BITSET_BITSET_HPP