// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.
#include "etl/complex.hpp"

#include "etl/type_traits.hpp"

#include "catch2/catch_template_test_macros.hpp"

TEMPLATE_TEST_CASE("complex: complex<T>", "[complex]", unsigned char,
    unsigned short, unsigned int, unsigned long, unsigned long long,
    signed char, short, int, long, long long, float, double, long double)
{
    using T = TestType;

    auto tc = etl::complex<T> {};
    REQUIRE(tc.real() == T { 0 });
    REQUIRE(tc.imag() == T { 0 });

    auto re = etl::complex<T> { T { 1 } };
    REQUIRE(re.real() == T { 1 });
    REQUIRE(re.imag() == T { 0 });

    auto im = etl::complex<T> { T { 1 }, T { 2 } };
    REQUIRE(im.real() == T { 1 });
    REQUIRE(im.imag() == T { 2 });

    tc = re;
    REQUIRE(tc.real() == T { 1 });
    REQUIRE(tc.imag() == T { 0 });
    REQUIRE(etl::real(tc) == T { 1 });
    REQUIRE(etl::imag(tc) == T { 0 });
    REQUIRE(real(tc) == T { 1 }); // ADL
    REQUIRE(imag(tc) == T { 0 }); // ADL

    tc *= T { 2 };
    REQUIRE(tc.real() == T { 2 });
    REQUIRE(tc.imag() == T { 0 });

    tc.real(T { 1 });
    tc.imag(T { 2 });
    REQUIRE(tc.real() == T { 1 });
    REQUIRE(tc.imag() == T { 2 });

    // unary +
    tc = +tc;
    REQUIRE(tc.real() == T { 1 });
    REQUIRE(tc.imag() == T { 2 });

    if constexpr (etl::is_signed_v<T>) {
        // unary -
        tc = -tc;
        REQUIRE(tc.real() == T { -1 });
        REQUIRE(tc.imag() == T { -2 });
    }
}

TEST_CASE("complex: literals", "[complex]")
{
    using namespace etl::complex_literals;

    auto f = 2_if;
    REQUIRE(f.real() == 0.0F);
    REQUIRE(f.imag() == 2.0F);

    auto d = 2_i;
    REQUIRE(d.real() == 0.0);
    REQUIRE(d.imag() == 2.0);

    auto ld = 2_il;
    REQUIRE(ld.real() == 0.0L);
    REQUIRE(ld.imag() == 2.0L);
}