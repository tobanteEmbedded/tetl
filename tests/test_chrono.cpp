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

#include "etl/chrono.hpp"
#include "etl/warning.hpp"

#include "catch2/catch.hpp"

TEMPLATE_TEST_CASE("chrono/duration: construct", "[chrono]", etl::int8_t,
                   etl::int16_t, etl::int32_t, etl::int64_t, float, double)
{
    auto d1 = etl::chrono::duration<TestType> {};
    etl::ignore_unused(d1);
}

TEMPLATE_TEST_CASE("chrono/duration: min,max,zero", "[chrono]", etl::int8_t,
                   etl::int16_t, etl::int32_t, etl::int64_t, float, double)
{
    using duration_t = etl::chrono::duration<TestType>;
    REQUIRE(duration_t::max().count() > duration_t::min().count());
}

TEMPLATE_TEST_CASE("chrono/duration: count", "[chrono]", etl::int8_t,
                   etl::int16_t, etl::int32_t, etl::int64_t, float, double)
{
    REQUIRE(etl::chrono::duration<TestType> {}.count() == 0);
    REQUIRE(etl::chrono::nanoseconds {}.count() == 0);
    REQUIRE(etl::chrono::milliseconds {}.count() == 0);
    REQUIRE(etl::chrono::seconds {}.count() == 0);
}

TEST_CASE("chrono/duration: operator\"\"", "[chrono]")
{
    using namespace etl::literals;
    auto const hour = 1_h;
    REQUIRE(hour.count() == etl::chrono::hours {1}.count());
}
