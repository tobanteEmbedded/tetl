// SPDX-License-Identifier: BSL-1.0

#include <etl/bitset.hpp>

#include <etl/cstddef.hpp>
#include <etl/string_view.hpp>
#include <etl/utility.hpp>

#include "testing/testing.hpp"

template <etl::size_t N>
static constexpr auto test_bitset() -> bool
{
    using namespace etl::string_view_literals;

    {
        // empty
        auto bits = etl::bitset<N>{};
        CHECK(bits.none());
        CHECK_FALSE(bits.test(0));
    }

    {
        CHECK(etl::bitset<N>(0b0000'0000).none());

        CHECK(etl::bitset<N>(0b0000'0001).count() == 1);
        CHECK(etl::bitset<N>(0b0000'0011).count() == 2);
        CHECK(etl::bitset<N>(0b0000'0111).count() == 3);
        CHECK(etl::bitset<N>(0b0000'1111).count() == 4);

        CHECK(etl::bitset<N>(0b1000'1111).count() == 5);
        CHECK(etl::bitset<N>(0b1100'1111).count() == 6);
        CHECK(etl::bitset<N>(0b1110'1111).count() == 7);
        CHECK(etl::bitset<N>(0b1111'1111).count() == 8);
    }

    {
        // string_view
        constexpr auto npos = etl::string_view::npos;

        CHECK(etl::bitset<N>("00000000"_sv).none());

        CHECK(etl::bitset<N>("00000001"_sv).count() == 1);
        CHECK(etl::bitset<N>("00000011"_sv).count() == 2);
        CHECK(etl::bitset<N>("00000111"_sv).count() == 3);
        CHECK(etl::bitset<N>("00001111"_sv).count() == 4);

        CHECK(etl::bitset<N>("10001111"_sv).count() == 5);
        CHECK(etl::bitset<N>("11001111"_sv).count() == 6);
        CHECK(etl::bitset<N>("11101111"_sv).count() == 7);
        CHECK(etl::bitset<N>("11111111"_sv).count() == 8);

        CHECK(etl::bitset<N>("AAAAAAAA"_sv, 0, npos, 'A', 'B').none());

        CHECK(etl::bitset<N>("AAAAAAAB"_sv, 0, npos, 'A', 'B').count() == 1);
        CHECK(etl::bitset<N>("AAAAAABB"_sv, 0, npos, 'A', 'B').count() == 2);
        CHECK(etl::bitset<N>("AAAAABBB"_sv, 0, npos, 'A', 'B').count() == 3);
        CHECK(etl::bitset<N>("AAAABBBB"_sv, 0, npos, 'A', 'B').count() == 4);

        CHECK(etl::bitset<N>("BAAABBBB"_sv, 0, npos, 'A', 'B').count() == 5);
        CHECK(etl::bitset<N>("BBAABBBB"_sv, 0, npos, 'A', 'B').count() == 6);
        CHECK(etl::bitset<N>("BBBABBBB"_sv, 0, npos, 'A', 'B').count() == 7);
        CHECK(etl::bitset<N>("BBBBBBBB"_sv, 0, npos, 'A', 'B').count() == 8);
    }

    {
        // char const*
        CHECK(etl::bitset<N>("00000000").none());

        CHECK(etl::bitset<N>("00000001").count() == 1);
        CHECK(etl::bitset<N>("00000011").count() == 2);
        CHECK(etl::bitset<N>("00000111").count() == 3);
        CHECK(etl::bitset<N>("00001111").count() == 4);

        CHECK(etl::bitset<N>("10001111").count() == 5);
        CHECK(etl::bitset<N>("11001111").count() == 6);
        CHECK(etl::bitset<N>("11101111").count() == 7);
        CHECK(etl::bitset<N>("11111111").count() == 8);

        CHECK(etl::bitset<N>("AAAAAAAA", 8, 'A', 'B').none());

        CHECK(etl::bitset<N>("AAAAAAAB", 8, 'A', 'B').count() == 1);
        CHECK(etl::bitset<N>("AAAAAABB", 8, 'A', 'B').count() == 2);
        CHECK(etl::bitset<N>("AAAAABBB", 8, 'A', 'B').count() == 3);
        CHECK(etl::bitset<N>("AAAABBBB", 8, 'A', 'B').count() == 4);

        CHECK(etl::bitset<N>("BAAABBBB", 8, 'A', 'B').count() == 5);
        CHECK(etl::bitset<N>("BBAABBBB", 8, 'A', 'B').count() == 6);
        CHECK(etl::bitset<N>("BBBABBBB", 8, 'A', 'B').count() == 7);
        CHECK(etl::bitset<N>("BBBBBBBB", 8, 'A', 'B').count() == 8);
    }

    {
        auto bits = etl::bitset<N>{};
        bits.set();
        CHECK(bits.all());
        CHECK(bits.any());
        CHECK(bits.test(1));
        CHECK(bits[2]);
    }

    {
        auto bits = etl::bitset<N>{};
        for (etl::size_t i = 0; i < bits.size(); ++i) {
            bits.set(i);
            CHECK(bits.test(i));

            bits.flip(i);
            CHECK_FALSE(bits.test(i));
            CHECK_FALSE(etl::as_const(bits)[i]);
        }
    }

    {
        auto bits = etl::bitset<N>{};
        CHECK(bits.none());

        bits.set(0);
        bits.set(1);
        CHECK(bits.test(0));
        CHECK(bits.test(1));
        CHECK(bits.any());

        bits.reset(1);
        CHECK_FALSE(bits.test(1));
        CHECK(bits.any());

        bits.reset();
        CHECK(bits.none());
    }
    {
        auto bits = etl::bitset<N>{};
        CHECK(bits.none());
        bits.flip();
        CHECK(bits.all());
        bits.flip();
        CHECK(bits.none());
    }

    {
        auto lhs = etl::bitset<N>{};
        auto rhs = etl::bitset<N>{};
        CHECK(rhs == lhs);
        CHECK(lhs == rhs);
        CHECK_FALSE(rhs != lhs);
        CHECK_FALSE(lhs != rhs);

        rhs.flip();
        CHECK_FALSE(rhs == lhs);
        CHECK_FALSE(lhs == rhs);
        CHECK(rhs != lhs);
        CHECK(lhs != rhs);
    }

    {
        using ref_type = typename etl::bitset<N>::reference;
        auto bits      = etl::bitset<N>{};

        ref_type r1 = bits[0];
        CHECK_FALSE(static_cast<bool>(r1));

        r1 = true;
        CHECK(static_cast<bool>(r1));

        r1 = false;
        CHECK(~r1);
        CHECK_FALSE(static_cast<bool>(r1));

        bits.set(1);
        ref_type r2 = bits[1];
        CHECK(static_cast<bool>(r2));
        r2.flip();
        CHECK_FALSE(static_cast<bool>(r2));
        r2.flip();
        CHECK(static_cast<bool>(r2));

        r2 = r1;
        CHECK_FALSE(static_cast<bool>(r2));
    }

    {
        if constexpr (N <= etl::numeric_limits<unsigned long>::digits) {
            CHECK(etl::bitset<N>{0U}.to_ulong() == 0UL);
            CHECK(etl::bitset<N>{1U}.to_ulong() == 1UL);

            CHECK(etl::bitset<N>{0b0000'1111U}.to_ulong() == 15UL);
            CHECK(etl::bitset<N>{0b1111'1111U}.to_ulong() == 255UL);
        }

        if constexpr (N <= etl::numeric_limits<unsigned long long>::digits) {
            CHECK(etl::bitset<N>{0U}.to_ullong() == 0ULL);
            CHECK(etl::bitset<N>{1U}.to_ullong() == 1ULL);

            CHECK(etl::bitset<N>{0b0000'1111U}.to_ullong() == 15ULL);
            CHECK(etl::bitset<N>{0b1111'1111U}.to_ullong() == 255ULL);
        }
    }

    {
        auto rhs = etl::bitset<N>{};
        auto lhs = etl::bitset<N>{};
        CHECK(rhs.none());

        rhs &= lhs;
        CHECK(rhs.none());

        lhs.flip();
        rhs &= lhs;
        CHECK(rhs.none());

        rhs.flip();
        rhs &= lhs;
        CHECK(rhs.all());
    }

    {
        auto rhs = etl::bitset<N>{};
        auto lhs = etl::bitset<N>{};
        CHECK(rhs.none());

        rhs |= lhs;
        CHECK(rhs.none());

        lhs.flip();
        rhs |= lhs;
        CHECK(rhs.all());

        rhs |= lhs;
        CHECK(rhs.all());
    }

    {
        auto rhs = etl::bitset<N>{};
        auto lhs = etl::bitset<N>{};
        CHECK(rhs.none());

        rhs ^= lhs;
        CHECK(rhs.none());

        lhs.flip();
        rhs ^= lhs;
        CHECK(rhs.all());

        rhs ^= lhs;
        CHECK(rhs.none());
    }

    {
        auto bits = etl::bitset<N>{};
        CHECK(bits.none());
        bits = ~bits;
        CHECK(bits.all());
    }

    {
        etl::bitset<N> b1("0110"_sv);
        etl::bitset<N> b2("0011"_sv);
        CHECK((b1 & b2).count() == 1);
        CHECK((b1 | b2).count() == 3);
        CHECK((b1 ^ b2).count() == 2);
    }

    {
        auto const bits = etl::bitset<8>{0b0010'1010};
        CHECK(bits.template to_string<16>() == "00101010"_sv);
        CHECK(bits.template to_string<16>('*') == "**1*1*1*"_sv);
        CHECK(bits.template to_string<16>('O', 'X') == "OOXOXOXO"_sv);
    }

    return true;
}

static constexpr auto test_all() -> bool
{
    CHECK(test_bitset<8>());
    CHECK(test_bitset<16>());
    CHECK(test_bitset<32>());
    CHECK(test_bitset<64>());
    CHECK(test_bitset<128>());
    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
