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
#include "etl/chrono.hpp"

#include "etl/warning.hpp"

#include <chrono>

#include "catch2/catch_template_test_macros.hpp"

TEMPLATE_TEST_CASE("chrono/duration: construct", "[chrono]", etl::int8_t,
    etl::int16_t, etl::int32_t, etl::int64_t, float, double)
{
    auto d1 = etl::chrono::duration<TestType> {};
    etl::ignore_unused(d1);
}

TEST_CASE("chrono/duration: construct(ratio)", "[chrono]")
{
    using etl::chrono::milliseconds;
    using etl::chrono::minutes;
    using etl::chrono::seconds;

    SECTION("seconds to milliseconds")
    {
        auto const sec   = seconds { 1 };
        auto const milli = milliseconds { sec };
        REQUIRE(milli.count() == 1'000);
    }

    SECTION("seconds to minutes")
    {
        auto const minute = minutes { 1 };
        auto const sec    = seconds { minute };
        REQUIRE(sec.count() == 60);
    }

    SECTION("float to float")
    {
        using seconds_f   = etl::chrono::duration<float, etl::ratio<1>>;
        using minutes_f   = etl::chrono::duration<float, etl::ratio<60>>;
        auto const minute = minutes_f { 1.0F };
        auto const sec    = seconds_f { minute };
        REQUIRE(sec.count() == 60.0F);
    }

    SECTION("double to int")
    {
        using milliseconds_f = etl::chrono::duration<double, etl::milli>;
        auto const sec       = seconds { 1 };
        auto const milli     = milliseconds_f(sec);
        REQUIRE(milli.count() == 1'000.0);
    }
}

TEMPLATE_TEST_CASE("chrono/duration: min,max,zero", "[chrono]", etl::int8_t,
    etl::int16_t, etl::int32_t, etl::int64_t, float, double)
{
    using duration_t = etl::chrono::duration<TestType>;
    REQUIRE(duration_t::max().count() > duration_t::min().count());
    REQUIRE(duration_t::max().count() > duration_t::zero().count());
}

TEMPLATE_TEST_CASE("chrono/duration: operator++ & operator--", "[chrono]",
    etl::int8_t, etl::int16_t, etl::int32_t, etl::int64_t)
{
    using duration_t = etl::chrono::duration<TestType>;
    auto dur         = duration_t { 0 };
    REQUIRE(dur++.count() == 0);
    REQUIRE(dur.count() == 1);
    REQUIRE(dur--.count() == 1);
    REQUIRE(dur.count() == 0);
    ++dur;
    REQUIRE(dur.count() == 1);
    --dur;
    REQUIRE(dur.count() == 0);

    etl::chrono::hours h(1);
    etl::chrono::minutes m = ++h;
    m--;
    REQUIRE(m.count() == 119);
}

TEMPLATE_TEST_CASE("chrono/duration: count", "[chrono]", etl::int8_t,
    etl::int16_t, etl::int32_t, etl::int64_t, float, double)
{
    REQUIRE(etl::chrono::duration<TestType> {}.count() == 0);
    REQUIRE(etl::chrono::nanoseconds {}.count() == 0);
    REQUIRE(etl::chrono::milliseconds {}.count() == 0);
    REQUIRE(etl::chrono::seconds {}.count() == 0);
}

TEST_CASE("chrono/duration: common_type<duration>", "[chrono]")
{
    SECTION("ms & us")
    {
        using ms = etl::chrono::milliseconds;
        using us = etl::chrono::microseconds;
        STATIC_REQUIRE(etl::is_same_v<etl::common_type<ms, us>::type, us>);
        STATIC_REQUIRE(etl::is_same_v<etl::common_type<us, ms>::type, us>);
    }

    SECTION("ms & ns")
    {
        using ms = etl::chrono::milliseconds;
        using ns = etl::chrono::nanoseconds;
        STATIC_REQUIRE(etl::is_same_v<etl::common_type<ms, ns>::type, ns>);
        STATIC_REQUIRE(etl::is_same_v<etl::common_type<ns, ms>::type, ns>);
    }
}

TEST_CASE("chrono/duration: operator==", "[chrono]")
{
    using etl::chrono::microseconds;
    using etl::chrono::milliseconds;
    using etl::chrono::seconds;

    REQUIRE(seconds { 1 } == seconds { 1 });
    REQUIRE(milliseconds { 42 } == milliseconds { 42 });
    REQUIRE(microseconds { 143 } == microseconds { 143 });
    REQUIRE(seconds { 1 } == milliseconds { 1'000 });

    REQUIRE_FALSE(seconds { 1 } == seconds { 0 });
    REQUIRE_FALSE(milliseconds { 42 } == milliseconds { 143 });
    REQUIRE_FALSE(microseconds { 143 } == microseconds { 42 });
}

TEST_CASE("chrono/duration: operator!=", "[chrono]")
{
    using etl::chrono::microseconds;
    using etl::chrono::milliseconds;
    using etl::chrono::seconds;

    REQUIRE(seconds { 1 } != seconds { 0 });
    REQUIRE(milliseconds { 42 } != milliseconds { 143 });
    REQUIRE(microseconds { 143 } != microseconds { 42 });

    REQUIRE_FALSE(seconds { 1 } != seconds { 1 });
    REQUIRE_FALSE(milliseconds { 42 } != milliseconds { 42 });
    REQUIRE_FALSE(microseconds { 143 } != microseconds { 143 });
    REQUIRE_FALSE(seconds { 1 } != milliseconds { 1'000 });
}

TEST_CASE("chrono/duration: operator<", "[chrono]")
{
    using etl::chrono::microseconds;
    using etl::chrono::milliseconds;
    using etl::chrono::seconds;

    REQUIRE(seconds { 0 } < seconds { 1 });
    REQUIRE(milliseconds { 999 } < seconds { 1 });
    REQUIRE(milliseconds { 42 } < milliseconds { 143 });
    REQUIRE(microseconds { 143 } < microseconds { 1'000 });

    REQUIRE_FALSE(seconds { 1 } < seconds { 1 });
    REQUIRE_FALSE(milliseconds { 42 } < milliseconds { 42 });
    REQUIRE_FALSE(microseconds { 143 } < microseconds { 143 });
    REQUIRE_FALSE(seconds { 1 } < milliseconds { 1'000 });
}

TEST_CASE("chrono/duration: operator<=", "[chrono]")
{
    using etl::chrono::microseconds;
    using etl::chrono::milliseconds;
    using etl::chrono::seconds;

    REQUIRE(seconds { 0 } <= seconds { 1 });
    REQUIRE(milliseconds { 999 } <= seconds { 1 });
    REQUIRE(milliseconds { 1000 } <= seconds { 1 });
    REQUIRE(milliseconds { 42 } <= milliseconds { 143 });
    REQUIRE(microseconds { 143 } <= microseconds { 1'000 });
    REQUIRE(seconds { 1 } <= seconds { 1 });
}

TEST_CASE("chrono/duration: operator>", "[chrono]")
{
    using etl::chrono::microseconds;
    using etl::chrono::milliseconds;
    using etl::chrono::seconds;

    REQUIRE_FALSE(seconds { 0 } > seconds { 1 });
    REQUIRE_FALSE(milliseconds { 999 } > seconds { 1 });
    REQUIRE_FALSE(milliseconds { 42 } > milliseconds { 143 });
    REQUIRE_FALSE(microseconds { 143 } > microseconds { 1'000 });

    REQUIRE(milliseconds { 1'000 } > milliseconds { 42 });
    REQUIRE(microseconds { 144 } > microseconds { 143 });
    REQUIRE(seconds { 1 } > milliseconds { 999 });
}

TEST_CASE("chrono/duration: operator>=", "[chrono]")
{
    using etl::chrono::microseconds;
    using etl::chrono::milliseconds;
    using etl::chrono::seconds;

    REQUIRE_FALSE(seconds { 0 } >= seconds { 1 });
    REQUIRE_FALSE(milliseconds { 999 } >= seconds { 1 });
    REQUIRE_FALSE(milliseconds { 42 } >= milliseconds { 143 });
    REQUIRE_FALSE(microseconds { 143 } >= microseconds { 1'000 });

    REQUIRE(milliseconds { 1'000 } >= milliseconds { 42 });
    REQUIRE(microseconds { 144 } >= microseconds { 143 });
    REQUIRE(seconds { 1 } >= milliseconds { 1'000 });
}

TEST_CASE("chrono/duration: abs", "[chrono]")
{
    using etl::chrono::microseconds;
    using etl::chrono::milliseconds;

    REQUIRE(etl::chrono::abs(microseconds { -10 }) == microseconds { 10 });
    REQUIRE(etl::chrono::abs(milliseconds { -143 }) == milliseconds { 143 });
}

TEST_CASE("chrono/duration: duration_cast", "[chrono]")
{
    using etl::chrono::duration_cast;
    using etl::chrono::microseconds;
    using etl::chrono::milliseconds;
    using etl::chrono::seconds;

    REQUIRE(duration_cast<microseconds>(milliseconds { 1 }).count() == 1'000);
    REQUIRE(duration_cast<seconds>(milliseconds { 1'000 }).count() == 1);
    REQUIRE(duration_cast<microseconds>(milliseconds { 143 }).count() == 143'000);
}

// TEST_CASE("chrono/duration: floor", "[chrono]")
//{
//  using ms = etl::chrono::milliseconds;
//  using us = etl::chrono::microseconds;
//  REQUIRE(etl::chrono::floor<us>(ms {30}).count() == us {30}.count());
//}

TEST_CASE("chrono/duration: operator\"\"_h (hour)", "[chrono]")
{
    using namespace etl::literals;
    auto const hour = 1_h;
    REQUIRE(hour.count() == etl::chrono::hours { 1 }.count());
}

TEST_CASE("chrono/duration: operator\"\"_min (minute)", "[chrono]")
{
    using namespace etl::literals;
    auto const minute = 1_min;
    REQUIRE(minute.count() == etl::chrono::minutes { 1 }.count());
}

TEST_CASE("chrono/duration: operator\"\"_s (seconds)", "[chrono]")
{
    using namespace etl::literals;
    auto const seconds = 1_s;
    REQUIRE(seconds.count() == etl::chrono::seconds { 1 }.count());
}

TEST_CASE("chrono/duration: operator\"\"_ms (milliseconds)", "[chrono]")
{
    using namespace etl::literals;
    auto const milliseconds = 1_ms;
    REQUIRE(milliseconds.count() == etl::chrono::milliseconds { 1 }.count());
}

TEST_CASE("chrono/duration: operator\"\"_ns (microseconds)", "[chrono]")
{
    using namespace etl::literals;
    auto const microseconds = 10_us;
    REQUIRE(microseconds.count() == etl::chrono::microseconds { 10 }.count());
}

TEST_CASE("chrono/duration: operator\"\"_ns (nanoseconds)", "[chrono]")
{
    using namespace etl::literals;
    auto const nanoseconds = 10_ns;
    REQUIRE(nanoseconds.count() == etl::chrono::nanoseconds { 10 }.count());
}

template <typename T>
struct null_clock {
    using rep            = T;
    using period         = etl::ratio<1>;
    using duration       = etl::chrono::duration<rep, period>;
    using time_point     = etl::chrono::time_point<null_clock>;
    bool const is_steady = false;

    [[nodiscard]] auto now() noexcept -> time_point { return time_point {}; }
};

TEMPLATE_TEST_CASE("chrono/duration: time_point", "[chrono]", etl::int8_t,
    etl::int16_t, etl::int32_t, etl::int64_t, float, double)
{
    auto null = etl::chrono::time_point<null_clock<TestType>> {};
    CHECK(null.time_since_epoch().count() == TestType { 0 });
}
