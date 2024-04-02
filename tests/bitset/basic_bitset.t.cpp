// SPDX-License-Identifier: BSL-1.0

#include <etl/bitset.hpp>

#include "testing/testing.hpp"

template <etl::size_t Bits, typename Word>
constexpr auto test() -> bool
{
    using bitset = etl::basic_bitset<Bits, Word>;

    {
        auto set = bitset{};
        CHECK(set.count() == 0);
        CHECK(set.none());
        CHECK_FALSE(set.all());
        CHECK_FALSE(set.any());

        set.flip(0);
        CHECK(set[0]);
        CHECK(set.count() == 1);
        CHECK(set.any());
        CHECK_FALSE(set.none());

        set.set(0, false);
        CHECK(set.count() == 0);
        CHECK(set.none());
        CHECK_FALSE(set[0]);
        CHECK_FALSE(set.any());
    }

    {
        auto const ones = bitset().set();
        CHECK(ones.count() == Bits);
        CHECK(ones.all());
        CHECK(ones.any());
        CHECK_FALSE(ones.none());
    }

    {
        auto const ones = bitset().flip();
        CHECK(ones.count() == Bits);
        CHECK(ones.all());
        CHECK(ones.any());
        CHECK_FALSE(ones.none());
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
