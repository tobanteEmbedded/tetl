// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_BITSET_BASIC_BITSET_HPP
#define TETL_BITSET_BASIC_BITSET_HPP

#include <etl/_algorithm/all_of.hpp>
#include <etl/_algorithm/any_of.hpp>
#include <etl/_algorithm/fill.hpp>
#include <etl/_algorithm/transform.hpp>
#include <etl/_array/array.hpp>
#include <etl/_bit/flip_bit.hpp>
#include <etl/_bit/popcount.hpp>
#include <etl/_bit/reset_bit.hpp>
#include <etl/_bit/set_bit.hpp>
#include <etl/_bit/test_bit.hpp>
#include <etl/_concepts/unsigned_integral.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_functional/plus.hpp>
#include <etl/_limits/numeric_limits.hpp>
#include <etl/_numeric/transform_reduce.hpp>

namespace etl {

/// \ingroup bitset
template <etl::size_t Bits, etl::unsigned_integral WordType = etl::size_t>
struct basic_bitset {
    constexpr basic_bitset() = default;

    [[nodiscard]] constexpr auto size() const noexcept -> etl::size_t { return Bits; }

    [[nodiscard]] constexpr auto operator[](etl::size_t pos) const -> bool
    {
        return etl::test_bit(_words[word_index(pos)], offset_in_word(pos));
    }

    [[nodiscard]] constexpr auto all() const noexcept -> bool
    {
        if constexpr (not has_padding) {
            return etl::all_of(_words.cbegin(), _words.cend(), [](auto word) { return word == ones; });
        } else {
            return count() == size();
        }
    }

    [[nodiscard]] constexpr auto any() const noexcept -> bool
    {
        if constexpr (not has_padding) {
            return etl::any_of(_words.cbegin(), _words.cend(), [](auto word) { return word != WordType(0); });
        } else {
            return count() > 0;
        }
    }

    [[nodiscard]] constexpr auto none() const noexcept -> bool
    {
        if constexpr (not has_padding) {
            return etl::all_of(_words.cbegin(), _words.cend(), [](auto word) { return word == WordType(0); });
        } else {
            return count() == 0;
        }
    }

    [[nodiscard]] constexpr auto count() const noexcept -> etl::size_t
    {
        return etl::transform_reduce(_words.cbegin(), _words.cend(), etl::size_t(0), etl::plus(), [](auto word) {
            return static_cast<etl::size_t>(etl::popcount(word));
        });
    }

    constexpr auto set() noexcept -> basic_bitset&
    {
        if constexpr (not has_padding) {
            etl::fill(_words.begin(), _words.end(), ones);
        } else {
            // TODO: Improve
            for (auto i = etl::size_t(0); i < size(); ++i) {
                set(i, true);
            }
        }

        return *this;
    }

    constexpr auto set(etl::size_t pos, bool value = true) -> basic_bitset&
    {
        return transform_bit(pos, [value](auto word, auto bit) { return etl::set_bit(word, bit, value); });
    }

    constexpr auto reset() noexcept -> basic_bitset&
    {
        etl::fill(_words.begin(), _words.end(), WordType(0));
        return *this;
    }

    constexpr auto reset(etl::size_t pos) -> basic_bitset&
    {
        return transform_bit(pos, [](auto word, auto bit) { return etl::reset_bit(word, bit); });
    }

    constexpr auto flip() noexcept -> basic_bitset&
    {
        if constexpr (not has_padding) {
            etl::transform(_words.cbegin(), _words.cend(), _words.begin(), [](auto word) {
                return static_cast<WordType>(~word);
            });
        } else {
            // TODO: Improve
            for (auto i = etl::size_t(0); i < size(); ++i) {
                flip(i);
            }
        }

        return *this;
    }

    constexpr auto flip(etl::size_t pos) -> basic_bitset&
    {
        return transform_bit(pos, [](auto word, auto bit) { return etl::flip_bit(word, bit); });
    }

private:
    static constexpr auto ones          = etl::numeric_limits<WordType>::max();
    static constexpr auto bits_per_word = static_cast<size_t>(etl::numeric_limits<WordType>::digits);
    static constexpr auto num_words     = (Bits + bits_per_word - 1) / bits_per_word;
    static constexpr auto has_padding   = (Bits % bits_per_word) != 0;

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
