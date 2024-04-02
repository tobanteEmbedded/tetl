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

    [[nodiscard]] constexpr auto operator[](etl::size_t pos) const -> bool
    {
        auto& word     = _words[word_index(pos)];
        auto const bit = static_cast<WordType>(offset_in_word(pos));
        return etl::test_bit(word, bit);
    }

    [[nodiscard]] constexpr auto all() const noexcept -> bool { return count() == Bits; }

    [[nodiscard]] constexpr auto any() const noexcept -> bool { return count() > 0; }

    [[nodiscard]] constexpr auto none() const noexcept -> bool { return count() == 0; }

    [[nodiscard]] constexpr auto count() const noexcept -> etl::size_t
    {
        return etl::transform_reduce(_words.cbegin(), _words.cend(), etl::size_t(0), etl::plus(), [](auto word) {
            return static_cast<etl::size_t>(etl::popcount(word));
        });
    }

    constexpr auto set() noexcept -> basic_bitset&
    {
        // etl::fill(_words.begin(), _words.end(), ones);
        // TODO: Improve
        for (auto i = etl::size_t(0); i < Bits; ++i) {
            set(i, true);
        }

        return *this;
    }

    constexpr auto set(etl::size_t pos, bool value = true) -> basic_bitset&
    {
        auto& word     = _words[word_index(pos)];
        auto const bit = static_cast<WordType>(offset_in_word(pos));
        word           = etl::set_bit(word, bit, value);
        return *this;
    }

    constexpr auto reset() noexcept -> basic_bitset&
    {
        etl::fill(_words.begin(), _words.end(), WordType(0));
        return *this;
    }

    constexpr auto reset(etl::size_t pos) -> basic_bitset&
    {
        auto& word     = _words[word_index(pos)];
        auto const bit = static_cast<WordType>(offset_in_word(pos));
        word           = etl::reset_bit(word, bit);
        return *this;
    }

    constexpr auto flip() noexcept -> basic_bitset&
    {
        // etl::transform(_words.cbegin(), _words.cend(), _words.begin(), [](auto word) {
        //     return static_cast<WordType>(~word);
        // });

        // TODO: Improve
        for (auto i = etl::size_t(0); i < Bits; ++i) {
            flip(i);
        }
        return *this;
    }

    constexpr auto flip(etl::size_t pos) -> basic_bitset&
    {
        auto& word     = _words[word_index(pos)];
        auto const bit = static_cast<WordType>(offset_in_word(pos));
        word           = etl::flip_bit(word, bit);
        return *this;
    }

private:
    static constexpr auto ones          = etl::numeric_limits<WordType>::max();
    static constexpr auto bits_per_word = static_cast<size_t>(etl::numeric_limits<WordType>::digits);
    static constexpr auto num_words     = (Bits + bits_per_word - 1) / bits_per_word;

    [[nodiscard]] static constexpr auto word_index(etl::size_t pos) -> etl::size_t { return pos / bits_per_word; }

    [[nodiscard]] static constexpr auto offset_in_word(etl::size_t pos) -> etl::size_t
    {
        return pos & (bits_per_word - 1U);
    }

    etl::array<WordType, num_words> _words{};
};

} // namespace etl

#endif // TETL_BITSET_BASIC_BITSET_HPP
