// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_BITSET_BITSET_HPP
#define TETL_BITSET_BITSET_HPP

#include <etl/_algorithm/min.hpp>
#include <etl/_bit/set_bit.hpp>
#include <etl/_bitset/basic_bitset.hpp>
#include <etl/_contracts/check.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_limits/numeric_limits.hpp>
#include <etl/_string/basic_inplace_string.hpp>
#include <etl/_string_view/basic_string_view.hpp>

namespace etl {

/// The class template bitset represents a fixed-size sequence of Bits bits.
/// Bitsets can be manipulated by standard logic operators.
/// \headerfile etl/bitset.hpp
/// \ingroup bitset
template <etl::size_t Bits>
struct bitset {
    using reference = basic_bitset<Bits, etl::size_t>::reference;

    /// Constructs a bitset with all bits set to zero.
    constexpr bitset() noexcept = default;

    /// Constructs a bitset, initializing the first (rightmost, least
    /// significant) M bit positions to the corresponding bit values of val,
    /// where M is the smaller of the number of bits in an unsigned long long
    /// and the number of bits Bits in the bitset being constructed. If M is less
    /// than Bits (the bitset is longer than 64 bits, for typical implementations
    /// of unsigned long long), the remaining bit positions are initialized to
    /// zeroes.
    constexpr bitset(unsigned long long val) noexcept
        : _bits(val)
    {
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
        auto const len = etl::min<decltype(pos)>(n, str.size() - pos);
        TETL_PRECONDITION(len >= 0);
        TETL_PRECONDITION(len <= size());

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
    constexpr auto set() noexcept -> bitset&
    {
        _bits.set();
        return *this;
    }

    /// Sets the bit at the given position to the given value.
    ///
    /// \param pos Index of the bit to be modified.
    /// \param value The new value for the bit.
    /// \returns *this
    constexpr auto set(etl::size_t pos, bool value = true) -> bitset&
    {
        TETL_PRECONDITION(pos < size());
        _bits.unchecked_set(pos, value);
        return *this;
    }

    /// Sets all bits to false.
    constexpr auto reset() noexcept -> bitset&
    {
        _bits.reset();
        return *this;
    }

    /// Sets the bit at position pos to false.
    ///
    /// \param pos Index of the bit to be reset.
    /// \returns *this
    constexpr auto reset(size_t pos) noexcept -> bitset&
    {
        TETL_PRECONDITION(pos < size());
        _bits.unchecked_reset(pos);
        return *this;
    }

    /// Flips all bits (like operator~, but in-place).
    constexpr auto flip() noexcept -> bitset&
    {
        _bits.flip();
        return *this;
    }

    /// Flips the bit at the position pos.
    ///
    /// \param pos Index of the bit to be reset.
    /// \returns *this
    constexpr auto flip(size_t pos) noexcept -> bitset&
    {
        TETL_PRECONDITION(pos < size());
        _bits.unchecked_flip(pos);
        return *this;
    }

    /// Returns a reference like proxy to the bit at the position pos.
    /// Perfoms no bounds checking.
    ///
    /// \param pos Index of the bit.
    [[nodiscard]] constexpr auto operator[](size_t const pos) -> reference
    {
        TETL_PRECONDITION(pos < size());
        return _bits[pos];
    }

    /// Returns the value of the bit at the position pos. Perfoms no
    /// bounds checking.
    ///
    /// \param pos Index of the bit.
    [[nodiscard]] constexpr auto operator[](size_t const pos) const -> bool
    {
        TETL_PRECONDITION(pos < size());
        return _bits[pos];
    }

    /// Returns the value of the bit at the position pos. Perfoms no
    /// bounds checking.
    ///
    /// \param pos Index of the bit.
    [[nodiscard]] constexpr auto test(size_t const pos) const -> bool
    {
        TETL_PRECONDITION(pos < size());
        return _bits.unchecked_test(pos);
    }

    /// Checks if all bits are set to true.
    [[nodiscard]] constexpr auto all() const noexcept -> bool
    {
        return _bits.all();
    }

    /// Checks if any bits are set to true.
    [[nodiscard]] constexpr auto any() const noexcept -> bool
    {
        return _bits.any();
    }

    /// Checks if none bits are set to true.
    [[nodiscard]] constexpr auto none() const noexcept -> bool
    {
        return _bits.none();
    }

    /// Returns the number of bits that are set to true.
    [[nodiscard]] constexpr auto count() const noexcept -> size_t
    {
        return _bits.count();
    }

    /// Returns the number of bits that the bitset holds.
    [[nodiscard]] constexpr auto size() const noexcept -> size_t
    {
        return _bits.size();
    }

    /// Returns true if all of the bits in *this and rhs are equal.
    [[nodiscard]] constexpr auto operator==(bitset const& rhs) const noexcept -> bool
    {
        return _bits == rhs._bits;
    }

    /// Sets the bits to the result of binary AND on corresponding pairs
    /// of bits of *this and other.
    constexpr auto operator&=(bitset const& other) noexcept -> bitset&
    {
        _bits &= other._bits;
        return *this;
    }

    /// Sets the bits to the result of binary OR on corresponding pairs
    /// of bits of *this and other.
    constexpr auto operator|=(bitset const& other) noexcept -> bitset&
    {
        _bits |= other._bits;
        return *this;
    }

    /// Sets the bits to the result of binary XOR on corresponding pairs
    /// of bits of *this and other.
    constexpr auto operator^=(bitset const& other) noexcept -> bitset&
    {
        _bits ^= other._bits;
        return *this;
    }

    /// Returns a temporary copy of *this with all bits flipped (binary NOT).
    constexpr auto operator~() const noexcept -> bitset
    {
        return bitset(*this).flip();
    }

    /// Converts the contents of the bitset to a string. Uses zero to
    /// represent bits with value of false and one to represent bits with value
    /// of true. The resulting string contains Bits characters with the first
    /// character corresponds to the last (Bits-1th) bit and the last character
    /// corresponding to the first bit.
    /// \todo Currently truncates the low bits, if the string is large enough.
    template <size_t Capacity, typename CharT = char, typename Traits = char_traits<CharT>>
        requires(Capacity >= Bits)
    [[nodiscard]] constexpr auto to_string(CharT zero = CharT('0'), CharT one = CharT('1')) const
        -> basic_inplace_string<CharT, Capacity, Traits>
    {
        auto str = basic_inplace_string<CharT, Capacity, Traits>{};
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
        requires(etl::numeric_limits<unsigned long>::digits >= Bits)
    {
        return to_unsigned_type<unsigned long>();
    }

    /// Converts the contents of the bitset to an unsigned long long
    /// integer. The first bit corresponds to the least significant digit of the
    /// number and the last bit corresponds to the most significant digit.
    [[nodiscard]] constexpr auto to_ullong() const noexcept -> unsigned long long
        requires(etl::numeric_limits<unsigned long long>::digits >= Bits)
    {
        return to_unsigned_type<unsigned long long>();
    }

    /// Performs binary AND between two bitsets, lhs and rhs.
    friend constexpr auto operator&(bitset const& lhs, bitset const& rhs) noexcept -> bitset
    {
        return bitset(lhs) &= rhs;
    }

    /// Performs binary OR between two bitsets, lhs and rhs.
    friend constexpr auto operator|(bitset const& lhs, bitset const& rhs) noexcept -> bitset
    {
        return bitset(lhs) |= rhs;
    }

    /// Performs binary XOR between two bitsets, lhs and rhs.
    friend constexpr auto operator^(bitset const& lhs, bitset const& rhs) noexcept -> bitset
    {
        return bitset(lhs) ^= rhs;
    }

private:
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

    basic_bitset<Bits, etl::size_t> _bits;
};

} // namespace etl

#endif // TETL_BITSET_BITSET_HPP
