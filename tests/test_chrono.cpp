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

namespace
{
template <typename T, typename S>
auto durationDiff(const T& t, const S& s) ->
    typename std::common_type<T, S>::type
{
    typedef typename std::common_type<T, S>::type Common;
    return Common(t) - Common(s);
}
}  // namespace
TEST_CASE("chrono/duration: common_type<duration>", "[chrono]")
{
    using milliseconds = std::chrono::milliseconds;
    using microseconds = std::chrono::microseconds;

    auto ms = milliseconds {30};
    REQUIRE(ms.count() == 30);
    auto us = microseconds {1100};
    REQUIRE(us.count() == 1100);
    auto diff = durationDiff(ms, us);
    REQUIRE(diff.count() == 28900);
}

TEST_CASE("chrono/duration: operator\"\"_h (hour)", "[chrono]")
{
    using namespace etl::literals;
    auto const hour = 1_h;
    REQUIRE(hour.count() == etl::chrono::hours {1}.count());
}

TEST_CASE("chrono/duration: operator\"\"_min (minute)", "[chrono]")
{
    using namespace etl::literals;
    auto const minute = 1_min;
    REQUIRE(minute.count() == etl::chrono::minutes {1}.count());
}

TEST_CASE("chrono/duration: operator\"\"_s (seconds)", "[chrono]")
{
    using namespace etl::literals;
    auto const seconds = 1_s;
    REQUIRE(seconds.count() == etl::chrono::seconds {1}.count());
}

TEST_CASE("chrono/duration: operator\"\"_ms (milliseconds)", "[chrono]")
{
    using namespace etl::literals;
    auto const milliseconds = 1_ms;
    REQUIRE(milliseconds.count() == etl::chrono::milliseconds {1}.count());
}

TEST_CASE("chrono/duration: operator\"\"_ns (microseconds)", "[chrono]")
{
    using namespace etl::literals;
    auto const microseconds = 10_us;
    REQUIRE(microseconds.count() == etl::chrono::microseconds {10}.count());
}

TEST_CASE("chrono/duration: operator\"\"_ns (nanoseconds)", "[chrono]")
{
    using namespace etl::literals;
    auto const nanoseconds = 10_ns;
    REQUIRE(nanoseconds.count() == etl::chrono::nanoseconds {10}.count());
}
