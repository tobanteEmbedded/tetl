// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/chrono.hpp>
    #include <etl/cstdint.hpp>
    #include <etl/limits.hpp>
    #include <etl/ratio.hpp>
    #include <etl/type_traits.hpp>
#endif

template <typename T>
static constexpr auto test() -> bool
{
    {
        auto d1 = etl::chrono::duration<T>{};
        CHECK(d1.count() == T(0));
    }

    {
        auto const sec   = etl::chrono::seconds{1};
        auto const milli = etl::chrono::milliseconds{sec};
        CHECK(milli.count() == 1'000);
    }

    {
        auto const minute = etl::chrono::minutes{1};
        auto const sec    = etl::chrono::seconds{minute};
        CHECK(sec.count() == 60);
    }

    {
        using seconds_f   = etl::chrono::duration<T, etl::ratio<1>>;
        using minutes_f   = etl::chrono::duration<T, etl::ratio<60>>;
        auto const minute = minutes_f{T(1)};
        auto const sec    = seconds_f{minute};
        CHECK(sec.count() == T(60));
    }

    {
        using duration_t = etl::chrono::duration<T>;
        CHECK(duration_t::max().count() > duration_t::min().count());
        CHECK(duration_t::max().count() > duration_t::zero().count());
    }

    {
        using duration_t = etl::chrono::duration<T>;
        auto dur         = duration_t{T{0}};

        auto o = dur++;
        CHECK(o.count() == 0);
        CHECK(dur.count() == 1);
        o = dur--;
        CHECK(o.count() == 1);
        CHECK(dur.count() == 0);
        ++dur;
        CHECK(dur.count() == 1);
        --dur;
        CHECK(dur.count() == 0);

        etl::chrono::hours h(1);
        etl::chrono::minutes m = ++h;
        m--;
        CHECK(m.count() == 119);
    }

    {
        CHECK(etl::chrono::duration<T>{}.count() == 0);
        CHECK(etl::chrono::nanoseconds{}.count() == 0);
        CHECK(etl::chrono::milliseconds{}.count() == 0);
        CHECK(etl::chrono::seconds{}.count() == 0);
    }

    {
        using ms = etl::chrono::milliseconds;
        using us = etl::chrono::microseconds;
        CHECK_SAME_TYPE(etl::common_type<ms, us>::type, us);
        CHECK_SAME_TYPE(etl::common_type<us, ms>::type, us);
    }

    {
        using ms = etl::chrono::milliseconds;
        using ns = etl::chrono::nanoseconds;
        CHECK_SAME_TYPE(etl::common_type<ms, ns>::type, ns);
        CHECK_SAME_TYPE(etl::common_type<ns, ms>::type, ns);
    }

    if constexpr (etl::is_integral_v<T>) {
        using ms = etl::chrono::duration<T, etl::milli>;
        using s  = etl::chrono::duration<T, etl::ratio<1>>;

        CHECK(s{T(1)} + s{T(0)} == s{T(1)});
        CHECK(s{T(1)} + ms{T(0)} == s{T(1)});
        CHECK(ms{T(1)} + s{T(0)} == ms{T(1)});
        CHECK(ms{T(1)} + ms{T(0)} == ms{T(1)});

        CHECK(s{T(1)} + ms{T(500)} == ms{T(1'500)});
        CHECK(ms{T(500)} + s{T(1)} == ms{T(1'500)});
    }

    if constexpr (etl::is_integral_v<T>) {
        using ms  = etl::chrono::duration<T, etl::milli>;
        using sec = etl::chrono::duration<T, etl::ratio<1>>;

        CHECK(sec{T(1)} - sec{T(0)} == sec{T(1)});
        CHECK(sec{T(1)} - ms{T(0)} == sec{T(1)});
        CHECK(ms{T(1)} - sec{T(0)} == ms{T(1)});
        CHECK(ms{T(1)} - ms{T(0)} == ms{T(1)});

        CHECK(sec{T(1)} - ms{T(500)} == ms{T(500)});
        CHECK(ms{T(500)} - sec{T(1)} == ms{T(-500)});
    }

    if constexpr (etl::is_integral_v<T>) {
        using sec_t = etl::chrono::duration<T, etl::ratio<1>>;

        CHECK(sec_t{T{1}} / sec_t{T{1}} == T{1});
        CHECK(sec_t{T{2}} / sec_t{T{1}} == T{2});
        CHECK(sec_t{T{4}} / sec_t{T{1}} == T{4});
        CHECK(sec_t{T{4}} / sec_t{T{2}} == T{2});
    }

    if constexpr (etl::is_integral_v<T>) {
        using sec_t = etl::chrono::duration<T, etl::ratio<1>>;

        CHECK(sec_t(T(1)) % sec_t(T(1)) == sec_t(T(0)));
        CHECK(sec_t(T(2)) % sec_t(T(1)) == sec_t(T(0)));
        CHECK(sec_t(T(4)) % sec_t(T(1)) == sec_t(T(0)));
        CHECK(sec_t(T(4)) % sec_t(T(2)) == sec_t(T(0)));

        CHECK(sec_t(T(5)) % sec_t(T(2)) == sec_t(T(1)));
        CHECK(sec_t(T(4)) % sec_t(T(3)) == sec_t(T(1)));
    }

    CHECK(etl::chrono::seconds{1} == etl::chrono::seconds{1});
    CHECK(etl::chrono::milliseconds{42} == etl::chrono::milliseconds{42});
    CHECK(etl::chrono::microseconds{143} == etl::chrono::microseconds{143});
    CHECK(etl::chrono::seconds{1} == etl::chrono::milliseconds{1'000});

    CHECK_FALSE(etl::chrono::seconds{1} == etl::chrono::seconds{0});
    CHECK_FALSE(etl::chrono::milliseconds{42} == etl::chrono::milliseconds{143});
    CHECK_FALSE(etl::chrono::microseconds{143} == etl::chrono::microseconds{42});

    CHECK(etl::chrono::seconds{1} != etl::chrono::seconds{0});
    CHECK(etl::chrono::milliseconds{42} != etl::chrono::milliseconds{143});
    CHECK(etl::chrono::microseconds{143} != etl::chrono::microseconds{42});

    CHECK_FALSE(etl::chrono::seconds{1} != etl::chrono::seconds{1});
    CHECK_FALSE(etl::chrono::milliseconds{42} != etl::chrono::milliseconds{42});
    CHECK_FALSE(etl::chrono::microseconds{143} != etl::chrono::microseconds{143});
    CHECK_FALSE(etl::chrono::seconds{1} != etl::chrono::milliseconds{1'000});

    CHECK(etl::chrono::seconds{0} < etl::chrono::seconds{1});
    CHECK(etl::chrono::milliseconds{999} < etl::chrono::seconds{1});
    CHECK(etl::chrono::milliseconds{42} < etl::chrono::milliseconds{143});
    CHECK(etl::chrono::microseconds{143} < etl::chrono::microseconds{1'000});

    CHECK_FALSE(etl::chrono::seconds{1} < etl::chrono::seconds{1});
    CHECK_FALSE(etl::chrono::milliseconds{42} < etl::chrono::milliseconds{42});
    CHECK_FALSE(etl::chrono::microseconds{143} < etl::chrono::microseconds{143});
    CHECK_FALSE(etl::chrono::seconds{1} < etl::chrono::milliseconds{1'000});

    CHECK(etl::chrono::seconds{0} <= etl::chrono::seconds{1});
    CHECK(etl::chrono::milliseconds{999} <= etl::chrono::seconds{1});
    CHECK(etl::chrono::milliseconds{1000} <= etl::chrono::seconds{1});
    CHECK(etl::chrono::milliseconds{42} <= etl::chrono::milliseconds{143});
    CHECK(etl::chrono::microseconds{143} <= etl::chrono::microseconds{1'000});
    CHECK(etl::chrono::seconds{1} <= etl::chrono::seconds{1});

    CHECK_FALSE(etl::chrono::seconds{0} > etl::chrono::seconds{1});
    CHECK_FALSE(etl::chrono::milliseconds{999} > etl::chrono::seconds{1});
    CHECK_FALSE(etl::chrono::milliseconds{42} > etl::chrono::milliseconds{143});
    CHECK_FALSE(etl::chrono::microseconds{143} > etl::chrono::microseconds{1'000});

    CHECK(etl::chrono::milliseconds{1'000} > etl::chrono::milliseconds{42});
    CHECK(etl::chrono::microseconds{144} > etl::chrono::microseconds{143});
    CHECK(etl::chrono::seconds{1} > etl::chrono::milliseconds{999});

    CHECK_FALSE(etl::chrono::seconds{0} >= etl::chrono::seconds{1});
    CHECK_FALSE(etl::chrono::milliseconds{999} >= etl::chrono::seconds{1});
    CHECK_FALSE(etl::chrono::milliseconds{42} >= etl::chrono::milliseconds{143});
    CHECK_FALSE(etl::chrono::microseconds{143} >= etl::chrono::microseconds{1'000});

    CHECK(etl::chrono::milliseconds{1'000} >= etl::chrono::milliseconds{42});
    CHECK(etl::chrono::microseconds{144} >= etl::chrono::microseconds{143});
    CHECK(etl::chrono::seconds{1} >= etl::chrono::milliseconds{1'000});

    CHECK(etl::chrono::abs(etl::chrono::minutes{-10}) == etl::chrono::minutes{10});
    CHECK(etl::chrono::abs(etl::chrono::minutes{-143}) == etl::chrono::minutes{143});

    CHECK(etl::chrono::duration_cast<etl::chrono::microseconds>(etl::chrono::milliseconds{1}).count() == 1'000);
    CHECK(etl::chrono::duration_cast<etl::chrono::seconds>(etl::chrono::milliseconds{1'000}).count() == 1);
    CHECK(etl::chrono::duration_cast<etl::chrono::microseconds>(etl::chrono::milliseconds{99}).count() == 99'000);

    {
        using namespace etl::literals;

        auto const h = 1_h;
        CHECK(h.count() == etl::chrono::hours{1}.count());

        auto const m = 1_min;
        CHECK(m.count() == etl::chrono::minutes{1}.count());

        auto const s = 1_s;
        CHECK(s.count() == etl::chrono::seconds{1}.count());

        auto const ms = 1_ms;
        CHECK(ms.count() == etl::chrono::milliseconds{1}.count());

        auto const us = 10_us;
        CHECK(us.count() == etl::chrono::microseconds{10}.count());

        auto const ns = 10_ns;
        CHECK(ns.count() == etl::chrono::nanoseconds{10}.count());
    }

    return true;
}

static constexpr auto test_all() -> bool
{
    CHECK(test<etl::int8_t>());
    CHECK(test<etl::int16_t>());
    CHECK(test<etl::int32_t>());
    CHECK(test<etl::int64_t>());
    CHECK(test<float>());
    CHECK(test<double>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
