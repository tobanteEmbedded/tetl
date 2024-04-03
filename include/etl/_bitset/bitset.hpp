// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_BITSET_BITSET_HPP
#define TETL_BITSET_BITSET_HPP

#include <etl/_algorithm/min.hpp>
#include <etl/_array/array.hpp>
#include <etl/_bit/set_bit.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_cstdint/uint_t.hpp>
#include <etl/_limits/numeric_limits.hpp>
#include <etl/_string/basic_static_string.hpp>
#include <etl/_string_view/string_view.hpp>

namespace etl {

/// \brief The class template bitset represents a fixed-size sequence of N bits.
/// Bitsets can be manipulated by standard logic operators.
/// \bug Add tests for sizes that are not a power of two. Broken at the moment.
/// \todo What if position index is out of bounds? Return nullptr?
/// \headerfile etl/bitset.hpp
/// \ingroup bitset
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
        /// Assigns a value to the referenced bit.
        constexpr auto operator=(bool value) noexcept -> reference&
        {
            if (value) {
                *_data |= (1U << _position);
                return *this;
            }

            *_data &= ~(1U << _position);
            return *this;
        }

        /// Assigns a value to the referenced bit.
        /// \returns *this
        constexpr auto operator=(reference const& x) noexcept -> reference&
        {
            (*this) = static_cast<bool>(x);
            return *this;
        }

        /// Returns the value of the referenced bit.
        [[nodiscard]] constexpr operator bool() const noexcept { return (*_data & (1U << _position)) != 0; }

        /// Returns the inverse of the referenced bit.
        [[nodiscard]] constexpr auto operator~() const noexcept -> bool { return !static_cast<bool>(*this); }

        /// Inverts the referenced bit.
        /// \returns *this
        constexpr auto flip() noexcept -> reference&
        {
            *_data ^= 1U << _position;
            return *this;
        }

    private:
        constexpr explicit reference(uint8_t* data, uint8_t position) : _data{data}, _position{position} { }

        friend bitset;
        uint8_t* _data;
        uint8_t _position;
    };

    /// Constructs a bitset with all bits set to zero.
    constexpr bitset() noexcept = default;

    /// Constructs a bitset, initializing the first (rightmost, least
    /// significant) M bit positions to the corresponding bit values of val,
    /// where M is the smaller of the number of bits in an unsigned long long
    /// and the number of bits N in the bitset being constructed. If M is less
    /// than N (the bitset is longer than 64 bits, for typical implementations
    /// of unsigned long long), the remaining bit positions are initialized to
    /// zeroes.
    constexpr bitset(unsigned long long val) noexcept
    {
        auto const n = min<size_t>(numeric_limits<decltype(val)>::digits, size());
        for (size_t i = 0; i < n; ++i) {
            if (((val >> i) & 1U) == 1U) {
                set(i);
            }
        }
    }

    /// Constructs a bitset using the characters in the
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
    explicit constexpr bitset(
        basic_string_view<CharT, Traits> const& str,
        typename basic_string_view<CharT, Traits>::size_type pos = 0,
        typename basic_string_view<CharT, Traits>::size_type n   = basic_string_view<CharT, Traits>::npos,
        CharT zero                                               = CharT('0'),
        CharT one                                                = CharT('1')
    )
        : bitset(0ULL)
    {
        auto const len = min<decltype(pos)>(n, str.size() - pos);
        TETL_ASSERT(len >= 0);
        TETL_ASSERT(len <= size());

        for (decltype(pos) i = 0; i < len; ++i) {
            if (Traits::eq(str[i + pos], one)) {
                set(i, true);
            }
            if (Traits::eq(str[i + pos], zero)) {
                set(i, false);
            }
        }
    }

    /// Constructs a bitset using the characters in the char const* str.
    ///
    /// \param str string used to initialize the bitset
    /// \param n number of characters to use from str
    /// \param zero alternate character for set bits in str
    /// \param one alternate character for unset bits in str
    template <typename CharT>
    explicit constexpr bitset(
        CharT const* str,
        typename basic_string_view<CharT>::size_type n = basic_string_view<CharT>::npos,
        CharT zero                                     = CharT('0'),
        CharT one                                      = CharT('1')
    )
        : bitset(
              n == basic_string_view<CharT>::npos ? basic_string_view<CharT>(str) : basic_string_view<CharT>(str, n),
              0,
              n,
              zero,
              one
          )
    {
    }

    /// Sets all bits to true.
    constexpr auto set() noexcept -> bitset<N>&
    {
        for (auto& b : _bits) {
            b = etl::numeric_limits<uint8_t>::max();
        }
        return *this;
    }

    /// Sets the bit at the given position to the given value.
    ///
    /// \param pos Index of the bit to be modified.
    /// \param value The new value for the bit.
    /// \returns *this
    constexpr auto set(etl::size_t pos, bool value = true) -> bitset<N>&
    {
        if (value) {
            auto& byte  = byte_for_position(pos);
            auto offset = offset_in_byte(pos);
            byte |= (1U << offset);
            return *this;
        }

        reset(pos);
        return *this;
    }

    /// Sets all bits to false.
    constexpr auto reset() noexcept -> bitset<N>&
    {
        _bits.fill(0);
        return *this;
    }

    /// Sets the bit at position pos to false.
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

    /// Flips all bits (like operator~, but in-place).
    constexpr auto flip() noexcept -> bitset<N>&
    {
        for (auto& b : _bits) {
            b = ~b;
        }
        return *this;
    }

    /// Flips the bit at the position pos.
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

    /// Returns a reference like proxy to the bit at the position pos.
    /// Perfoms no bounds checking.
    ///
    /// \param pos Index of the bit.
    [[nodiscard]] constexpr auto operator[](size_t const pos) -> reference
    {
        auto& byte  = byte_for_position(pos);
        auto offset = offset_in_byte(pos);
        return reference(&byte, offset);
    }

    /// Returns the value of the bit at the position pos. Perfoms no
    /// bounds checking.
    ///
    /// \param pos Index of the bit.
    [[nodiscard]] constexpr auto operator[](size_t const pos) const -> bool { return test(pos); }

    /// Returns the value of the bit at the position pos. Perfoms no
    /// bounds checking.
    ///
    /// \param pos Index of the bit.
    [[nodiscard]] constexpr auto test(size_t const pos) const -> bool
    {
        auto& byte  = byte_for_position(pos);
        auto offset = offset_in_byte(pos);
        return (byte & (1U << offset)) != 0;
    }

    /// Checks if all bits are set to true.
    [[nodiscard]] constexpr auto all() const noexcept -> bool { return count() == size(); }

    /// Checks if any bits are set to true.
    [[nodiscard]] constexpr auto any() const noexcept -> bool { return count() > 0; }

    /// Checks if none bits are set to true.
    [[nodiscard]] constexpr auto none() const noexcept -> bool { return count() == 0; }

    /// Returns the number of bits that are set to true.
    [[nodiscard]] constexpr auto count() const noexcept -> size_t
    {
        size_t count = 0;
        for (size_t i = 0; i < size(); ++i) {
            count += test(i) ? size_t{1} : 0;
        }
        return count;
    }

    /// Returns the number of bits that the bitset holds.
    [[nodiscard]] constexpr auto size() const noexcept -> size_t { return N; }

    /// Returns true if all of the bits in *this and rhs are equal.
    [[nodiscard]] constexpr auto operator==(bitset<N> const& rhs) const noexcept -> bool
    {
        for (size_t i = 0; i < size(); ++i) {
            if (test(i) != rhs.test(i)) {
                return false;
            }
        }

        return true;
    }

    /// Returns true if all of the bits in *this and rhs are not equal.
    [[nodiscard]] constexpr auto operator!=(bitset<N> const& rhs) const noexcept -> bool { return !(*this == rhs); }

    /// Sets the bits to the result of binary AND on corresponding pairs
    /// of bits of *this and other.
    constexpr auto operator&=(bitset<N> const& other) noexcept -> bitset<N>&
    {
        for (size_t i = 0; i < (size() >> 3); ++i) {
            _bits[i] &= other._bits[i];
        }
        return *this;
    }

    /// Sets the bits to the result of binary OR on corresponding pairs
    /// of bits of *this and other.
    constexpr auto operator|=(bitset<N> const& other) noexcept -> bitset<N>&
    {
        for (size_t i = 0; i < (size() >> 3); ++i) {
            _bits[i] |= other._bits[i];
        }
        return *this;
    }

    /// Sets the bits to the result of binary XOR on corresponding pairs
    /// of bits of *this and other.
    constexpr auto operator^=(bitset<N> const& other) noexcept -> bitset<N>&
    {
        for (size_t i = 0; i < (size() >> 3); ++i) {
            _bits[i] ^= other._bits[i];
        }
        return *this;
    }

    /// Returns a temporary copy of *this with all bits flipped (binary NOT).
    constexpr auto operator~() const noexcept -> bitset<N> { return bitset<N>(*this).flip(); }

    /// Converts the contents of the bitset to a string. Uses zero to
    /// represent bits with value of false and one to represent bits with value
    /// of true. The resulting string contains N characters with the first
    /// character corresponds to the last (N-1th) bit and the last character
    /// corresponding to the first bit.
    /// \todo Currently truncates the low bits, if the string is large enough.
    template <size_t Capacity, typename CharT = char, typename Traits = char_traits<CharT>>
    [[nodiscard]] constexpr auto
    to_string(CharT zero = CharT('0'), CharT one = CharT('1')) const -> basic_static_string<CharT, Capacity, Traits>
    {
        auto str = basic_static_string<CharT, Capacity, Traits>{};
        for (auto i{size() - 1U}; i != 0; --i) {
            str.push_back(test(i) ? one : zero);
        }
        str.push_back(test(0) ? one : zero);
        return str;
    }

    /// Converts the contents of the bitset to an unsigned long integer.
    /// The first bit corresponds to the least significant digit of the number
    /// and the last bit corresponds to the most significant digit.
    [[nodiscard]] constexpr auto to_ulong() const noexcept -> unsigned long
    {
        return to_unsigned_type<unsigned long>();
    }

    /// Converts the contents of the bitset to an unsigned long long
    /// integer. The first bit corresponds to the least significant digit of the
    /// number and the last bit corresponds to the most significant digit.
    [[nodiscard]] constexpr auto to_ullong() const noexcept -> unsigned long long
    {
        return to_unsigned_type<unsigned long long>();
    }

private:
    [[nodiscard]] constexpr auto byte_for_position(etl::size_t pos) const -> etl::uint8_t const&
    {
        TETL_ASSERT(pos < size());
        return _bits[pos >> 3U];
    }

    [[nodiscard]] constexpr auto byte_for_position(etl::size_t pos) -> etl::uint8_t&
    {
        TETL_ASSERT(pos < size());
        return _bits[pos >> 3U];
    }

    [[nodiscard]] constexpr auto offset_in_byte(etl::size_t pos) const noexcept -> etl::uint8_t { return pos & 0x7U; }

    template <typename UInt>
    [[nodiscard]] constexpr auto to_unsigned_type() const noexcept -> UInt
    {
        constexpr auto digits = static_cast<UInt>(etl::numeric_limits<UInt>::digits);
        auto const idx        = etl::min<UInt>(static_cast<UInt>(size()), digits);
        UInt result{};
        for (UInt i{0}; i != idx; ++i) {
            if (test(static_cast<etl::size_t>(i))) {
                result = etl::set_bit(result, i);
            }
        }
        return result;
    }

    static constexpr etl::size_t allocated_    = N >> 3U;
    etl::array<etl::uint8_t, allocated_> _bits = {};
};

/// Performs binary AND between two bitsets, lhs and rhs.
template <etl::size_t N>
[[nodiscard]] constexpr auto operator&(bitset<N> const& lhs, bitset<N> const& rhs) noexcept -> bitset<N>
{
    return bitset<N>(lhs) &= rhs;
}

/// Performs binary OR between two bitsets, lhs and rhs.
template <etl::size_t N>
[[nodiscard]] constexpr auto operator|(bitset<N> const& lhs, bitset<N> const& rhs) noexcept -> bitset<N>
{
    return bitset<N>(lhs) |= rhs;
}

/// Performs binary XOR between two bitsets, lhs and rhs.
template <etl::size_t N>
[[nodiscard]] constexpr auto operator^(bitset<N> const& lhs, bitset<N> const& rhs) noexcept -> bitset<N>
{
    return bitset<N>(lhs) ^= rhs;
}

} // namespace etl

#endif // TETL_BITSET_BITSET_HPP
