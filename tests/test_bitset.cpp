/*
Copyright (c) 2019-2021, Tobias Hienzsch
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
*/

#include "catch2/catch.hpp"

#include "etl/bitset.hpp"

TEMPLATE_TEST_CASE_SIG("bitset: construct()", "[bitset]", ((size_t N), N), 8, 16, 32, 64)
{
    auto bits = etl::bitset<N> {};
    CHECK(bits.none());
    CHECK_FALSE(bits.test(0));
}

TEMPLATE_TEST_CASE_SIG("bitset: construct(unsigned long long)", "[bitset]",
                       ((size_t N), N), 8, 16, 32, 64)
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

TEMPLATE_TEST_CASE_SIG("bitset: construct(basic_static_string)", "[bitset]",
                       ((size_t N), N), 8, 16, 32, 64)
{
    using String = etl::static_string<16>;
    CHECK(etl::bitset<N>(String("00000000")).none());

    CHECK(etl::bitset<N>(String("00000001")).count() == 1);
    CHECK(etl::bitset<N>(String("00000011")).count() == 2);
    CHECK(etl::bitset<N>(String("00000111")).count() == 3);
    CHECK(etl::bitset<N>(String("00001111")).count() == 4);

    CHECK(etl::bitset<N>(String("10001111")).count() == 5);
    CHECK(etl::bitset<N>(String("11001111")).count() == 6);
    CHECK(etl::bitset<N>(String("11101111")).count() == 7);
    CHECK(etl::bitset<N>(String("11111111")).count() == 8);

    CHECK(etl::bitset<N>(String("AAAAAAAA"), 0, String::npos, 'A', 'B').none());

    CHECK(etl::bitset<N>(String("AAAAAAAB"), 0, String::npos, 'A', 'B').count() == 1);
    CHECK(etl::bitset<N>(String("AAAAAABB"), 0, String::npos, 'A', 'B').count() == 2);
    CHECK(etl::bitset<N>(String("AAAAABBB"), 0, String::npos, 'A', 'B').count() == 3);
    CHECK(etl::bitset<N>(String("AAAABBBB"), 0, String::npos, 'A', 'B').count() == 4);

    CHECK(etl::bitset<N>(String("BAAABBBB"), 0, String::npos, 'A', 'B').count() == 5);
    CHECK(etl::bitset<N>(String("BBAABBBB"), 0, String::npos, 'A', 'B').count() == 6);
    CHECK(etl::bitset<N>(String("BBBABBBB"), 0, String::npos, 'A', 'B').count() == 7);
    CHECK(etl::bitset<N>(String("BBBBBBBB"), 0, String::npos, 'A', 'B').count() == 8);
}

TEMPLATE_TEST_CASE_SIG("bitset: set()", "[bitset]", ((size_t N), N), 8, 16, 32, 64)
{
    auto bits = etl::bitset<N> {};

    bits.set();
    CHECK(bits.all());
    CHECK(bits.any());
    CHECK(bits.test(1));
    CHECK(bits[2]);
}

TEMPLATE_TEST_CASE_SIG("bitset: set(pos)", "[bitset]", ((size_t N), N), 8, 16, 32, 64)
{
    auto bits = etl::bitset<N> {};
    for (size_t i = 0; i < bits.size(); ++i)
    {
        bits.set(i);
        CHECK(bits.test(i));
    }
}

TEMPLATE_TEST_CASE_SIG("bitset: reset()", "[bitset]", ((size_t N), N), 32, 64, 128)
{
    auto bits = etl::bitset<N> {};
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

TEMPLATE_TEST_CASE_SIG("bitset: flip()", "[bitset]", ((size_t N), N), 8, 16, 32, 64)
{
    auto bits = etl::bitset<N> {};
    CHECK(bits.none());
    bits.flip();
    CHECK(bits.all());
    bits.flip();
    CHECK(bits.none());
}

TEMPLATE_TEST_CASE_SIG("bitset: compare", "[bitset]", ((size_t N), N), 8, 16, 32, 64)
{
    auto lhs = etl::bitset<N> {};
    auto rhs = etl::bitset<N> {};
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

TEMPLATE_TEST_CASE_SIG("bitset: reference", "[bitset]", ((size_t N), N), 8, 16, 32, 64)
{
    using ref_type = typename etl::bitset<N>::reference;
    auto bits      = etl::bitset<N> {};

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

    r2 = r1;
    CHECK_FALSE(static_cast<bool>(r2));
}

TEMPLATE_TEST_CASE_SIG("bitset: operator&=", "[bitset]", ((size_t N), N), 8, 16, 32, 64)
{
    auto rhs = etl::bitset<N> {};
    auto lhs = etl::bitset<N> {};
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

TEMPLATE_TEST_CASE_SIG("bitset: operator|=", "[bitset]", ((size_t N), N), 8, 16, 32, 64)
{
    auto rhs = etl::bitset<N> {};
    auto lhs = etl::bitset<N> {};
    CHECK(rhs.none());

    rhs |= lhs;
    CHECK(rhs.none());

    lhs.flip();
    rhs |= lhs;
    CHECK(rhs.all());

    rhs |= lhs;
    CHECK(rhs.all());
}

TEMPLATE_TEST_CASE_SIG("bitset: operator^=", "[bitset]", ((size_t N), N), 8, 16, 32, 64)
{
    auto rhs = etl::bitset<N> {};
    auto lhs = etl::bitset<N> {};
    CHECK(rhs.none());

    rhs ^= lhs;
    CHECK(rhs.none());

    lhs.flip();
    rhs ^= lhs;
    CHECK(rhs.all());

    rhs ^= lhs;
    CHECK(rhs.none());
}

TEMPLATE_TEST_CASE_SIG("bitset: operator~", "[bitset]", ((size_t N), N), 8, 16, 32, 64)
{
    auto bits = etl::bitset<N> {};
    CHECK(bits.none());
    bits = ~bits;
    CHECK(bits.all());
}
