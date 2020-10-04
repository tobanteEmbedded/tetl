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

#include "etl/set.hpp"

#include "catch2/catch.hpp"

TEMPLATE_TEST_CASE("set/static_set: typedefs", "[set]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
    using set_t = etl::static_set<TestType, 16>;

    STATIC_REQUIRE(etl::is_same_v<TestType, typename set_t::value_type>);
    STATIC_REQUIRE(etl::is_same_v<TestType&, typename set_t::reference>);
    STATIC_REQUIRE(etl::is_same_v<TestType const&, typename set_t::const_reference>);
    STATIC_REQUIRE(etl::is_same_v<TestType*, typename set_t::pointer>);
    STATIC_REQUIRE(etl::is_same_v<TestType const*, typename set_t::const_pointer>);
    STATIC_REQUIRE(etl::is_same_v<TestType*, typename set_t::iterator>);
    STATIC_REQUIRE(etl::is_same_v<TestType const*, typename set_t::const_iterator>);
}

TEMPLATE_TEST_CASE("set/static_set: ctor(default)", "[set]", etl::uint8_t, etl::int8_t,
                   etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
                   etl::uint64_t, etl::int64_t, float, double, long double)
{
    SECTION("4")
    {
        auto set = etl::static_set<TestType, 4>();
        CHECK(set.size() == 0);
        CHECK(set.max_size() == 4);
        CHECK(set.empty());
        CHECK_FALSE(set.full());
    }

    SECTION("16")
    {
        auto set = etl::static_set<TestType, 16>();
        CHECK(set.size() == 0);
        CHECK(set.max_size() == 16);
        CHECK(set.empty());
        CHECK_FALSE(set.full());
    }
}