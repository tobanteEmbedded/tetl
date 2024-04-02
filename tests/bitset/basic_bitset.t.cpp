// SPDX-License-Identifier: BSL-1.0

#include <etl/bitset.hpp>

#include "testing/testing.hpp"

template <etl::size_t Bits, typename Word>
constexpr auto test() -> bool
{
    using bitset = etl::basic_bitset<Bits, Word>;

    CHECK(bitset() == bitset());
    CHECK(bitset(0b111) == bitset(0b111));

    CHECK_FALSE(bitset(0b111) == bitset());
    CHECK(bitset(0b111) != bitset());
    CHECK(bitset(0b111) != bitset(0b110));

    {
        auto set = bitset{};
        CHECK(set.count() == 0);
        CHECK(set.none());
        CHECK_FALSE(set.all());
        CHECK_FALSE(set.any());

        set.unchecked_flip(0);
        CHECK(set[0]);
        CHECK(set.count() == 1);
        CHECK(set.any());
        CHECK_FALSE(set.none());

        set.unchecked_set(0, false);
        CHECK(set.count() == 0);
        CHECK(set.none());
        CHECK_FALSE(set[0]);
        CHECK_FALSE(set.any());
    }

    {
        auto const ones = bitset(0b0000'0000).set();
        CHECK(ones.count() == Bits);
        CHECK(ones.all());
        CHECK(ones.any());
        CHECK_FALSE(ones.none());
    }

    if constexpr (Bits >= 4) {
        auto const set = bitset(0b1111).unchecked_reset(0).unchecked_flip(1);
        CHECK(set.count() == 2);
        CHECK(set.any());
        CHECK_FALSE(set.all());
        CHECK_FALSE(set.none());

        CHECK((bitset(0b111) & bitset(0b101)) == bitset(0b101));
        CHECK((bitset(0b111) | bitset(0b101)) == bitset(0b111));
        CHECK((bitset(0b111) ^ bitset(0b101)) == bitset(0b010));
    }

    return true;
}

template <typename Word>
constexpr auto test_word_type() -> bool
{
    CHECK(test<1, Word>());
    CHECK(test<2, Word>());
    CHECK(test<3, Word>());
    CHECK(test<7, Word>());
    CHECK(test<8, Word>());
    CHECK(test<9, Word>());
    CHECK(test<15, Word>());
    CHECK(test<16, Word>());
    CHECK(test<17, Word>());
    CHECK(test<64, Word>());
    CHECK(test<65, Word>());
    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test_word_type<unsigned char>());
    CHECK(test_word_type<unsigned short>());
    CHECK(test_word_type<unsigned int>());
    CHECK(test_word_type<unsigned long>());

#if not defined(TETL_WORKAROUND_AVR_BROKEN_TESTS)
    CHECK(test_word_type<unsigned long long>());
#endif

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
