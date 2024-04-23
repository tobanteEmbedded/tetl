// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_BITSET_BASIC_BITSET_HPP
#define TETL_BITSET_BASIC_BITSET_HPP

#include <etl/_algorithm/all_of.hpp>
#include <etl/_algorithm/any_of.hpp>
#include <etl/_algorithm/fill.hpp>
#include <etl/_algorithm/min.hpp>
#include <etl/_algorithm/transform.hpp>
#include <etl/_array/array.hpp>
#include <etl/_bit/flip_bit.hpp>
#include <etl/_bit/popcount.hpp>
#include <etl/_bit/reset_bit.hpp>
#include <etl/_bit/set_bit.hpp>
#include <etl/_bit/test_bit.hpp>
#include <etl/_concepts/unsigned_integral.hpp>
#include <etl/_contracts/check.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_functional/plus.hpp>
#include <etl/_iterator/prev.hpp>
#include <etl/_limits/numeric_limits.hpp>
#include <etl/_memory/addressof.hpp>
#include <etl/_numeric/transform_reduce.hpp>

namespace etl {

/// \headerfile etl/bitset.hpp
/// \ingroup bitset
template <etl::size_t Bits, etl::unsigned_integral WordType = etl::size_t>
struct basic_bitset {

    struct reference {

        constexpr auto operator=(bool x) noexcept -> reference&
        {
            *_word = etl::set_bit(*_word, _offset, x);
            return *this;
        }

        constexpr auto operator=(reference const& x) noexcept -> reference&
        {
            *_word = etl::set_bit(*_word, _offset, static_cast<bool>(x));
            return *this;
        }

        [[nodiscard]] constexpr operator bool() const noexcept { return etl::test_bit(*_word, _offset); }

        [[nodiscard]] constexpr auto operator~() const noexcept -> bool { return not static_cast<bool>(*this); }

        constexpr auto flip() noexcept -> reference&
        {
            *_word = etl::flip_bit(*_word, _offset);
            return *this;
        }

    private:
        constexpr explicit reference(WordType& word, WordType offset) noexcept
            : _word{etl::addressof(word)}
            , _offset{offset}
        {
        }

        WordType* _word;
        WordType _offset;

        friend basic_bitset;
    };

    /// Default constructor. Constructs a bitset with all bits set to zero.
    constexpr basic_bitset() = default;

    /// Constructs a bitset, initializing the first (rightmost, least significant)
    /// M bit positions to the corresponding bit values of val.
    constexpr basic_bitset(unsigned long long val) noexcept
    {
        auto const digits = static_cast<size_t>(etl::numeric_limits<unsigned long long>::digits);
        auto const m      = etl::min(digits, size());
        for (auto i = etl::size_t(0); i < m; ++i) {
            unchecked_set(i, etl::test_bit(val, static_cast<unsigned long long>(i)));
        }
    }

    /// Returns the number of bits that the bitset holds.
    [[nodiscard]] constexpr auto size() const noexcept -> etl::size_t { return Bits; }

    /// Returns true if the bit at position \p pos is set.
    /// \pre `pos < size()`
    [[nodiscard]] constexpr auto operator[](etl::size_t pos) const -> bool
    {
        TETL_PRECONDITION(pos < size());
        return unchecked_test(pos);
    }

    /// Returns a reference to the bit at position \p pos
    /// \pre `pos < size()`
    [[nodiscard]] constexpr auto operator[](etl::size_t pos) -> reference
    {
        TETL_PRECONDITION(pos < size());
        return reference{_words[word_index(pos)], offset_in_word(pos)};
    }

    /// Checks if all bits are set to true.
    [[nodiscard]] constexpr auto all() const noexcept -> bool
    {
        auto const allSet = [](auto word) { return word == ones; };

        if constexpr (has_padding) {
            auto const head = etl::all_of(_words.cbegin(), etl::prev(_words.cend()), allSet);
            auto const tail = _words[num_words - 1] == padding_mask_inv;
            return head and tail;
        } else {
            return etl::all_of(_words.cbegin(), _words.cend(), allSet);
        }
    }

    /// Checks if any bits are set to true.
    [[nodiscard]] constexpr auto any() const noexcept -> bool { return not none(); }

    /// Checks if none of the bits are set to true.
    [[nodiscard]] constexpr auto none() const noexcept -> bool
    {
        return etl::all_of(_words.cbegin(), _words.cend(), [](auto word) { return word == WordType(0); });
    }

    /// Returns the number of bits that are set to true.
    [[nodiscard]] constexpr auto count() const noexcept -> etl::size_t
    {
        return etl::transform_reduce(_words.cbegin(), _words.cend(), etl::size_t(0), etl::plus(), [](auto word) {
            return static_cast<etl::size_t>(etl::popcount(word));
        });
    }

    /// Returns true if the bit at position \p pos is set.
    /// \pre `pos < size()`
    [[nodiscard]] constexpr auto unchecked_test(etl::size_t pos) const -> bool
    {
        TETL_PRECONDITION(pos < size());
        return etl::test_bit(_words[word_index(pos)], offset_in_word(pos));
    }

    /// Sets all bits to true.
    constexpr auto set() noexcept -> basic_bitset&
    {
        if constexpr (has_padding) {
            etl::fill(_words.begin(), etl::prev(_words.end()), ones);
            _words[num_words - 1] = padding_mask_inv;
        } else {
            etl::fill(_words.begin(), _words.end(), ones);
        }

        return *this;
    }

    /// Set bit at position \p pos to \p value
    /// \pre `pos < size()`
    constexpr auto unchecked_set(etl::size_t pos, bool value = true) -> basic_bitset&
    {
        TETL_PRECONDITION(pos < size());
        return transform_bit(pos, [value](auto word, auto bit) { return etl::set_bit(word, bit, value); });
    }

    /// Sets all bits to false.
    constexpr auto reset() noexcept -> basic_bitset&
    {
        etl::fill(_words.begin(), _words.end(), WordType(0));
        return *this;
    }

    /// Sets the bit at position \p pos to false.
    /// \pre `pos < size()`
    constexpr auto unchecked_reset(etl::size_t pos) -> basic_bitset&
    {
        TETL_PRECONDITION(pos < size());
        return transform_bit(pos, [](auto word, auto bit) { return etl::reset_bit(word, bit); });
    }

    /// Flips all bits.
    constexpr auto flip() noexcept -> basic_bitset&
    {
        etl::transform(_words.cbegin(), _words.cend(), _words.begin(), [](auto word) {
            return static_cast<WordType>(~word);
        });

        if constexpr (has_padding) {
            _words[num_words - 1] &= padding_mask_inv;
        }

        return *this;
    }

    /// Flip bit at position \p pos
    /// \pre `pos < size()`
    constexpr auto unchecked_flip(etl::size_t pos) -> basic_bitset&
    {
        TETL_PRECONDITION(pos < size());
        return transform_bit(pos, [](auto word, auto bit) { return etl::flip_bit(word, bit); });
    }

    /// Sets the bits to the result of binary AND on corresponding pairs of bits of `*this` and `other`
    constexpr auto operator&=(basic_bitset const& other) noexcept -> basic_bitset&
    {
        etl::transform(_words.begin(), _words.end(), other._words.begin(), _words.begin(), [](auto lhs, auto rhs) {
            return static_cast<WordType>(lhs & rhs);
        });
        return *this;
    }

    /// Sets the bits to the result of binary OR on corresponding pairs of bits of `*this` and `other`
    constexpr auto operator|=(basic_bitset const& other) noexcept -> basic_bitset&
    {
        etl::transform(_words.begin(), _words.end(), other._words.begin(), _words.begin(), [](auto lhs, auto rhs) {
            return static_cast<WordType>(lhs | rhs);
        });
        return *this;
    }

    /// Sets the bits to the result of binary XOR on corresponding pairs of bits of `*this` and `other`
    constexpr auto operator^=(basic_bitset const& other) noexcept -> basic_bitset&
    {
        etl::transform(_words.begin(), _words.end(), other._words.begin(), _words.begin(), [](auto lhs, auto rhs) {
            return static_cast<WordType>(lhs ^ rhs);
        });
        return *this;
    }

    /// Returns true if all of the bits in \p lhs and \p rhs are equal.
    friend constexpr auto operator==(basic_bitset const& lhs, basic_bitset const& rhs) -> bool = default;

    /// Returns a basic_bitset containing the result of binary AND on corresponding pairs of bits of \p lhs and \p rhs.
    friend constexpr auto operator&(basic_bitset const& lhs, basic_bitset const& rhs) noexcept -> basic_bitset
    {
        return basic_bitset(lhs) &= rhs;
    }

    /// Returns a basic_bitset containing the result of binary OR on corresponding pairs of bits of \p lhs and \p rhs.
    friend constexpr auto operator|(basic_bitset const& lhs, basic_bitset const& rhs) noexcept -> basic_bitset
    {
        return basic_bitset(lhs) |= rhs;
    }

    /// Returns a basic_bitset containing the result of binary XOR on corresponding pairs of bits of \p lhs and \p rhs.
    friend constexpr auto operator^(basic_bitset const& lhs, basic_bitset const& rhs) noexcept -> basic_bitset
    {
        return basic_bitset(lhs) ^= rhs;
    }

private:
    static constexpr auto ones          = etl::numeric_limits<WordType>::max();
    static constexpr auto bits_per_word = static_cast<size_t>(etl::numeric_limits<WordType>::digits);
    static constexpr auto num_words     = (Bits + bits_per_word - 1) / bits_per_word;
    static constexpr auto padding       = num_words * bits_per_word - Bits;
    static constexpr auto has_padding   = padding != 0;
    static constexpr auto padding_mask  = [] {
        auto mask = WordType{};
        for (auto i{bits_per_word - padding}; i < bits_per_word; ++i) {
            mask = etl::set_bit(mask, static_cast<WordType>(i));
        }
        return mask;
    }();
    static constexpr auto padding_mask_inv = static_cast<WordType>(~padding_mask);

    [[nodiscard]] static constexpr auto word_index(etl::size_t pos) -> etl::size_t { return pos / bits_per_word; }

    [[nodiscard]] static constexpr auto offset_in_word(etl::size_t pos) -> WordType
    {
        return static_cast<WordType>(pos & (bits_per_word - etl::size_t(1)));
    }

    constexpr auto transform_bit(etl::size_t pos, auto op) -> basic_bitset&
    {
        auto& word = _words[word_index(pos)];
        word       = op(word, offset_in_word(pos));
        return *this;
    }

    etl::array<WordType, num_words> _words{};
};

} // namespace etl

#endif // TETL_BITSET_BASIC_BITSET_HPP
