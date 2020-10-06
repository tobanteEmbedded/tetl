/*
Copyright (c) 2019-2020, Tobias Hienzsch
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

#include "etl/concepts.hpp"

#include "catch2/catch.hpp"

#if defined(TAETL_CPP_STANDARD_20) && defined(__cpp_concepts)
namespace
{
auto floating_point_test(etl::floating_point auto /*unused*/) { return true; }

auto floating_point_test(auto /*unused*/) { return false; }
}  // namespace

TEST_CASE("concepts: floating_point", "[concepts]")
{
    CHECK(floating_point_test(143.0));
    CHECK(floating_point_test(143.0F));
    CHECK(floating_point_test(143.0l));

    CHECK_FALSE(floating_point_test(etl::int8_t(42)));
    CHECK_FALSE(floating_point_test(etl::uint8_t(42)));
    CHECK_FALSE(floating_point_test(etl::int16_t(143)));
    CHECK_FALSE(floating_point_test(etl::uint16_t(143)));
    CHECK_FALSE(floating_point_test(etl::int32_t(143)));
    CHECK_FALSE(floating_point_test(etl::uint32_t(143)));
    CHECK_FALSE(floating_point_test(etl::int64_t(143)));
    CHECK_FALSE(floating_point_test(etl::uint64_t(143)));
    CHECK_FALSE(floating_point_test(143));
    CHECK_FALSE(floating_point_test(143U));
}

namespace
{
auto integral_test(etl::integral auto /*unused*/) { return true; }

auto integral_test(auto /*unused*/) { return false; }
}  // namespace

TEST_CASE("concepts: integral", "[concepts]")
{
    CHECK(integral_test(etl::int8_t(42)));
    CHECK(integral_test(etl::uint8_t(42)));
    CHECK(integral_test(etl::int16_t(143)));
    CHECK(integral_test(etl::uint16_t(143)));
    CHECK(integral_test(etl::int32_t(143)));
    CHECK(integral_test(etl::uint32_t(143)));
    CHECK(integral_test(etl::int64_t(143)));
    CHECK(integral_test(etl::uint64_t(143)));
    CHECK(integral_test(143));
    CHECK(integral_test(143U));

    CHECK_FALSE(integral_test(143.0));
    CHECK_FALSE(integral_test(143.0F));
    CHECK_FALSE(integral_test(143.0l));
}

namespace
{
auto signed_integral_test(etl::signed_integral auto /*unused*/) { return true; }

auto signed_integral_test(auto /*unused*/) { return false; }
}  // namespace

TEST_CASE("concepts: signed_integral", "[concepts]")
{
    CHECK(signed_integral_test(etl::int8_t(42)));
    CHECK(signed_integral_test(etl::int16_t(143)));
    CHECK(signed_integral_test(etl::int32_t(143)));
    CHECK(signed_integral_test(etl::int64_t(143)));
    CHECK(signed_integral_test(143));

    CHECK_FALSE(signed_integral_test(etl::uint8_t(42)));
    CHECK_FALSE(signed_integral_test(etl::uint16_t(143)));
    CHECK_FALSE(signed_integral_test(etl::uint32_t(143)));
    CHECK_FALSE(signed_integral_test(etl::uint64_t(143)));
    CHECK_FALSE(signed_integral_test(143U));
    CHECK_FALSE(signed_integral_test(143.0));
    CHECK_FALSE(signed_integral_test(143.0F));
    CHECK_FALSE(signed_integral_test(143.0l));
}

namespace
{
auto unsigned_integral_test(etl::unsigned_integral auto /*unused*/) { return true; }

auto unsigned_integral_test(auto /*unused*/) { return false; }
}  // namespace

TEST_CASE("concepts: unsigned_integral", "[concepts]")
{
    CHECK(unsigned_integral_test(etl::uint8_t(42)));
    CHECK(unsigned_integral_test(etl::uint16_t(143)));
    CHECK(unsigned_integral_test(etl::uint32_t(143)));
    CHECK(unsigned_integral_test(etl::uint64_t(143)));
    CHECK(unsigned_integral_test(143U));

    CHECK_FALSE(unsigned_integral_test(etl::int8_t(42)));
    CHECK_FALSE(unsigned_integral_test(etl::int16_t(143)));
    CHECK_FALSE(unsigned_integral_test(etl::int32_t(143)));
    CHECK_FALSE(unsigned_integral_test(etl::int64_t(143)));
    CHECK_FALSE(unsigned_integral_test(143));
    CHECK_FALSE(unsigned_integral_test(143.0));
    CHECK_FALSE(unsigned_integral_test(143.0F));
    CHECK_FALSE(unsigned_integral_test(143.0l));
}

#endif
