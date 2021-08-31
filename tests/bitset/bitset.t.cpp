/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/bitset.hpp"

#include "etl/cstddef.hpp"
#include "etl/string_view.hpp"
#include "etl/utility.hpp"

#include "helper.hpp"

template <etl::size_t N>
constexpr auto test_bitset() -> bool
{
    using etl::bitset;
    using namespace etl::string_view_literals;

    {
        // empty
        auto bits = bitset<N> {};
        assert(bits.none());
        assert(!bits.test(0));
    }

    {
        assert(bitset<N>(0b0000'0000).none());

        assert(bitset<N>(0b0000'0001).count() == 1);
        assert(bitset<N>(0b0000'0011).count() == 2);
        assert(bitset<N>(0b0000'0111).count() == 3);
        assert(bitset<N>(0b0000'1111).count() == 4);

        assert(bitset<N>(0b1000'1111).count() == 5);
        assert(bitset<N>(0b1100'1111).count() == 6);
        assert(bitset<N>(0b1110'1111).count() == 7);
        assert(bitset<N>(0b1111'1111).count() == 8);
    }

    {
        // string_view
        constexpr auto npos = etl::string_view::npos;

        assert(bitset<N>("00000000"_sv).none());

        assert(bitset<N>("00000001"_sv).count() == 1);
        assert(bitset<N>("00000011"_sv).count() == 2);
        assert(bitset<N>("00000111"_sv).count() == 3);
        assert(bitset<N>("00001111"_sv).count() == 4);

        assert(bitset<N>("10001111"_sv).count() == 5);
        assert(bitset<N>("11001111"_sv).count() == 6);
        assert(bitset<N>("11101111"_sv).count() == 7);
        assert(bitset<N>("11111111"_sv).count() == 8);

        assert((bitset<N>("AAAAAAAA"_sv, 0, npos, 'A', 'B').none()));

        assert((bitset<N>("AAAAAAAB"_sv, 0, npos, 'A', 'B').count() == 1));
        assert((bitset<N>("AAAAAABB"_sv, 0, npos, 'A', 'B').count() == 2));
        assert((bitset<N>("AAAAABBB"_sv, 0, npos, 'A', 'B').count() == 3));
        assert((bitset<N>("AAAABBBB"_sv, 0, npos, 'A', 'B').count() == 4));

        assert((bitset<N>("BAAABBBB"_sv, 0, npos, 'A', 'B').count() == 5));
        assert((bitset<N>("BBAABBBB"_sv, 0, npos, 'A', 'B').count() == 6));
        assert((bitset<N>("BBBABBBB"_sv, 0, npos, 'A', 'B').count() == 7));
        assert((bitset<N>("BBBBBBBB"_sv, 0, npos, 'A', 'B').count() == 8));
    }

    {
        // char const*
        assert(bitset<N>("00000000").none());

        assert(bitset<N>("00000001").count() == 1);
        assert(bitset<N>("00000011").count() == 2);
        assert(bitset<N>("00000111").count() == 3);
        assert(bitset<N>("00001111").count() == 4);

        assert(bitset<N>("10001111").count() == 5);
        assert(bitset<N>("11001111").count() == 6);
        assert(bitset<N>("11101111").count() == 7);
        assert(bitset<N>("11111111").count() == 8);

        assert((bitset<N>("AAAAAAAA", 8, 'A', 'B').none()));

        assert((bitset<N>("AAAAAAAB", 8, 'A', 'B').count() == 1));
        assert((bitset<N>("AAAAAABB", 8, 'A', 'B').count() == 2));
        assert((bitset<N>("AAAAABBB", 8, 'A', 'B').count() == 3));
        assert((bitset<N>("AAAABBBB", 8, 'A', 'B').count() == 4));

        assert((bitset<N>("BAAABBBB", 8, 'A', 'B').count() == 5));
        assert((bitset<N>("BBAABBBB", 8, 'A', 'B').count() == 6));
        assert((bitset<N>("BBBABBBB", 8, 'A', 'B').count() == 7));
        assert((bitset<N>("BBBBBBBB", 8, 'A', 'B').count() == 8));
    }

    {
        auto bits = bitset<N> {};
        bits.set();
        assert(bits.all());
        assert(bits.any());
        assert(bits.test(1));
        assert(bits[2]);
    }

    {
        auto bits = bitset<N> {};
        for (etl::size_t i = 0; i < bits.size(); ++i) {
            bits.set(i);
            assert(bits.test(i));

            bits.flip(i);
            assert(!bits.test(i));
            assert(!etl::as_const(bits)[i]);
        }
    }

    {
        auto bits = etl::bitset<N> {};
        assert(bits.none());

        bits.set(0);
        bits.set(1);
        assert(bits.test(0));
        assert(bits.test(1));
        assert(bits.any());

        bits.reset(1);
        assert(!(bits.test(1)));
        assert(bits.any());

        bits.reset();
        assert(bits.none());
    }
    {
        auto bits = etl::bitset<N> {};
        assert(bits.none());
        bits.flip();
        assert(bits.all());
        bits.flip();
        assert(bits.none());
    }

    {
        auto lhs = etl::bitset<N> {};
        auto rhs = etl::bitset<N> {};
        assert(rhs == lhs);
        assert(lhs == rhs);
        assert(!(rhs != lhs));
        assert(!(lhs != rhs));

        rhs.flip();
        assert(!(rhs == lhs));
        assert(!(lhs == rhs));
        assert(rhs != lhs);
        assert(lhs != rhs);
    }

    {
        using ref_type = typename etl::bitset<N>::reference;
        auto bits      = etl::bitset<N> {};

        ref_type r1 = bits[0];
        assert(!(static_cast<bool>(r1)));

        r1 = true;
        assert(static_cast<bool>(r1));

        r1 = false;
        assert(~r1);
        assert(!(static_cast<bool>(r1)));

        bits.set(1);
        ref_type r2 = bits[1];
        assert(static_cast<bool>(r2));
        r2.flip();
        assert(!(static_cast<bool>(r2)));
        r2.flip();
        assert(static_cast<bool>(r2));

        r2 = r1;
        assert(!(static_cast<bool>(r2)));
    }

    {
        assert(etl::bitset<N> { 0U }.to_ulong() == 0UL);
        assert(etl::bitset<N> { 0U }.to_ullong() == 0ULL);

        assert(etl::bitset<N> { 1U }.to_ulong() == 1UL);
        assert(etl::bitset<N> { 1U }.to_ullong() == 1ULL);

        assert(etl::bitset<N> { 0b0000'1111U }.to_ulong() == 15UL);
        assert(etl::bitset<N> { 0b0000'1111U }.to_ullong() == 15ULL);

        assert(etl::bitset<N> { 0b1111'1111U }.to_ulong() == 255UL);
        assert(etl::bitset<N> { 0b1111'1111U }.to_ullong() == 255ULL);
    }

    {
        auto rhs = etl::bitset<N> {};
        auto lhs = etl::bitset<N> {};
        assert(rhs.none());

        rhs &= lhs;
        assert(rhs.none());

        lhs.flip();
        rhs &= lhs;
        assert(rhs.none());

        rhs.flip();
        rhs &= lhs;
        assert(rhs.all());
    }

    {
        auto rhs = etl::bitset<N> {};
        auto lhs = etl::bitset<N> {};
        assert(rhs.none());

        rhs |= lhs;
        assert(rhs.none());

        lhs.flip();
        rhs |= lhs;
        assert(rhs.all());

        rhs |= lhs;
        assert(rhs.all());
    }

    {
        auto rhs = etl::bitset<N> {};
        auto lhs = etl::bitset<N> {};
        assert(rhs.none());

        rhs ^= lhs;
        assert(rhs.none());

        lhs.flip();
        rhs ^= lhs;
        assert(rhs.all());

        rhs ^= lhs;
        assert(rhs.none());
    }

    {
        auto bits = etl::bitset<N> {};
        assert(bits.none());
        bits = ~bits;
        assert(bits.all());
    }

    {
        etl::bitset<N> b1("0110"_sv);
        etl::bitset<N> b2("0011"_sv);
        assert((b1 & b2).count() == 1);
        assert((b1 | b2).count() == 3);
        assert((b1 ^ b2).count() == 2);
    }

    {
        // TODO [tobi] Test other sizes
        auto const bits = etl::bitset<8> { 0b0010'1010 };
        assert((bits.template to_string<16>() == "00101010"_sv));
        assert((bits.template to_string<16>('*') == "**1*1*1*"_sv));
        assert((bits.template to_string<16>('O', 'X') == "OOXOXOXO"_sv));
    }

    return true;
}

constexpr auto test_all() -> bool
{
    assert(test_bitset<8>());
    assert(test_bitset<16>());
    assert(test_bitset<32>());
    assert(test_bitset<64>());
    assert(test_bitset<128>());
    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}