// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/bitset.hpp>
    #include <etl/cstddef.hpp>
    #include <etl/limits.hpp>
    #include <etl/string_view.hpp>
    #include <etl/utility.hpp>
#endif

template <etl::size_t Bits, typename Word>
static constexpr auto test() -> bool
{
    using bitset = etl::basic_bitset<Bits, Word>;

    {
        auto set = bitset{};
        CHECK(set.count() == 0);
        CHECK(set.none());
        CHECK_FALSE(set.all());
        CHECK_FALSE(set.any());

        set.unchecked_flip(0);
        CHECK(etl::as_const(set)[0]);
        CHECK(set[0]);
        CHECK(set.count() == 1);
        CHECK(set.any());
        CHECK_FALSE(set.none());

        set.unchecked_set(0, false);
        CHECK(set.count() == 0);
        CHECK_FALSE(set[0]);
    }

    {
        auto const ones = bitset(0b0000'0000).set();
        CHECK(ones.count() == Bits);
        CHECK(ones.all());
        CHECK(ones.any());
        CHECK_FALSE(ones.none());
    }

    if constexpr (Bits >= 4) {
        auto set = bitset(0b1111).unchecked_reset(0).unchecked_flip(1);
        CHECK(set.count() == 2);

        auto ref = set[0];
        ref      = true;
        CHECK(ref);
        CHECK_FALSE(~ref);

        ref = false;
        CHECK(~ref);
        CHECK_FALSE(etl::as_const(set)[0]);
        CHECK_FALSE(ref);

        ref.flip();
        CHECK(ref);
        CHECK(etl::as_const(set)[0]);

        ref = set[2];
        CHECK(ref);
        CHECK(etl::as_const(set)[2]);

        CHECK((bitset(0b111) & bitset(0b101)) == bitset(0b101));
        CHECK((bitset(0b111) | bitset(0b101)) == bitset(0b111));
        CHECK((bitset(0b111) ^ bitset(0b101)) == bitset(0b010));

        CHECK(bitset() == bitset());
        CHECK(bitset(0b111) == bitset(0b111));

        CHECK_FALSE(bitset(0b111) == bitset());
        CHECK(bitset(0b111) != bitset());
        CHECK(bitset(0b111) != bitset(0b110));

        CHECK(bitset(0b0000'0000).set() == bitset(0b0000'0000).flip());
        CHECK(bitset(0b0000'0000).set().reset() == bitset(0b0000'0000));
    }

    return true;
}

template <typename Word>
static constexpr auto test_word_type() -> bool
{
    CHECK(test<1, Word>());
    CHECK(test<7, Word>());
    CHECK(test<8, Word>());
    CHECK(test<9, Word>());
    CHECK(test<16, Word>());
    CHECK(test<65, Word>());
    return true;
}

static constexpr auto test_all() -> bool
{
    CHECK(test_word_type<unsigned char>());
    CHECK(test_word_type<unsigned short>());
    CHECK(test_word_type<unsigned int>());
    CHECK(test_word_type<unsigned long>());
    CHECK(test_word_type<unsigned long long>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
