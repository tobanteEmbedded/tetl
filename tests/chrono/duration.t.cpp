/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/chrono.hpp"

#include "etl/cstdint.hpp"
#include "etl/ratio.hpp"
#include "etl/type_traits.hpp"

#include "testing/testing.hpp"

using etl::chrono::microseconds;
using etl::chrono::milliseconds;
using etl::chrono::minutes;
using etl::chrono::seconds;

template <typename T>
constexpr auto test() -> bool
{
    {
        auto d1 = etl::chrono::duration<T> {};
        assert(d1.count() == T(0));
    }

    {
        auto const sec   = seconds { 1 };
        auto const milli = milliseconds { sec };
        assert(milli.count() == 1'000);
    }

    {
        auto const minute = minutes { 1 };
        auto const sec    = seconds { minute };
        assert(sec.count() == 60);
    }

    {
        using seconds_f   = etl::chrono::duration<T, etl::ratio<1>>;
        using minutes_f   = etl::chrono::duration<T, etl::ratio<60>>;
        auto const minute = minutes_f { T(1) };
        auto const sec    = seconds_f { minute };
        assert(sec.count() == T(60));
    }

    {
        using duration_t = etl::chrono::duration<T>;
        assert(duration_t::max().count() > duration_t::min().count());
        assert(duration_t::max().count() > duration_t::zero().count());
    }

    {
        using duration_t = etl::chrono::duration<T>;
        auto dur         = duration_t { T { 0 } };

        auto o = dur++;
        assert(o.count() == 0);
        assert(dur.count() == 1);
        o = dur--;
        assert(o.count() == 1);
        assert(dur.count() == 0);
        ++dur;
        assert(dur.count() == 1);
        --dur;
        assert(dur.count() == 0);

        etl::chrono::hours h(1);
        etl::chrono::minutes m = ++h;
        m--;
        assert(m.count() == 119);
    }

    {
        assert(etl::chrono::duration<T> {}.count() == 0);
        assert(etl::chrono::nanoseconds {}.count() == 0);
        assert(etl::chrono::milliseconds {}.count() == 0);
        assert(etl::chrono::seconds {}.count() == 0);
    }

    {
        using ms = etl::chrono::milliseconds;
        using us = etl::chrono::microseconds;
        assert((etl::is_same_v<etl::common_type<ms, us>::type, us>));
        assert((etl::is_same_v<etl::common_type<us, ms>::type, us>));
    }

    {
        using ms = etl::chrono::milliseconds;
        using ns = etl::chrono::nanoseconds;
        assert((etl::is_same_v<etl::common_type<ms, ns>::type, ns>));
        assert((etl::is_same_v<etl::common_type<ns, ms>::type, ns>));
    }

    if constexpr (etl::is_integral_v<T>) {
        using ms = etl::chrono::duration<T, etl::milli>;
        using s  = etl::chrono::duration<T, etl::ratio<1>>;

        assert(s { T(1) } + s { T(0) } == s { T(1) });
        assert(s { T(1) } + ms { T(0) } == s { T(1) });
        assert(ms { T(1) } + s { T(0) } == ms { T(1) });
        assert(ms { T(1) } + ms { T(0) } == ms { T(1) });

        assert(s { T(1) } + ms { T(500) } == ms { T(1'500) });
        assert(ms { T(500) } + s { T(1) } == ms { T(1'500) });
    }

    if constexpr (etl::is_integral_v<T>) {
        using ms  = etl::chrono::duration<T, etl::milli>;
        using sec = etl::chrono::duration<T, etl::ratio<1>>;

        assert(sec { 1 } - sec { 0 } == sec { 1 });
        assert(sec { 1 } - ms { 0 } == sec { 1 });
        assert(ms { 1 } - sec { 0 } == ms { 1 });
        assert(ms { 1 } - ms { 0 } == ms { 1 });

        assert(sec { 1 } - ms { 500 } == ms { 500 });
        assert(ms { 500 } - sec { 1 } == ms { -500 });
    }

    if constexpr (etl::is_integral_v<T>) {
        using sec_t = etl::chrono::duration<T, etl::ratio<1>>;

        assert(sec_t { T { 1 } } / sec_t { T { 1 } } == T { 1 });
        assert(sec_t { T { 2 } } / sec_t { T { 1 } } == T { 2 });
        assert(sec_t { T { 4 } } / sec_t { T { 1 } } == T { 4 });
        assert(sec_t { T { 4 } } / sec_t { T { 2 } } == T { 2 });
    }

    if constexpr (etl::is_integral_v<T>) {
        using sec_t = etl::chrono::duration<T, etl::ratio<1>>;

        assert(sec_t(T(1)) % sec_t(T(1)) == sec_t(T(0)));
        assert(sec_t(T(2)) % sec_t(T(1)) == sec_t(T(0)));
        assert(sec_t(T(4)) % sec_t(T(1)) == sec_t(T(0)));
        assert(sec_t(T(4)) % sec_t(T(2)) == sec_t(T(0)));

        assert(sec_t(T(5)) % sec_t(T(2)) == sec_t(T(1)));
        assert(sec_t(T(4)) % sec_t(T(3)) == sec_t(T(1)));
    }

    assert(seconds { 1 } == seconds { 1 });
    assert(milliseconds { 42 } == milliseconds { 42 });
    assert(microseconds { 143 } == microseconds { 143 });
    assert(seconds { 1 } == milliseconds { 1'000 });

    assert(!(seconds { 1 } == seconds { 0 }));
    assert(!(milliseconds { 42 } == milliseconds { 143 }));
    assert(!(microseconds { 143 } == microseconds { 42 }));

    assert(seconds { 1 } != seconds { 0 });
    assert(milliseconds { 42 } != milliseconds { 143 });
    assert(microseconds { 143 } != microseconds { 42 });

    assert(!(seconds { 1 } != seconds { 1 }));
    assert(!(milliseconds { 42 } != milliseconds { 42 }));
    assert(!(microseconds { 143 } != microseconds { 143 }));
    assert(!(seconds { 1 } != milliseconds { 1'000 }));

    assert(seconds { 0 } < seconds { 1 });
    assert(milliseconds { 999 } < seconds { 1 });
    assert(milliseconds { 42 } < milliseconds { 143 });
    assert(microseconds { 143 } < microseconds { 1'000 });

    assert(!(seconds { 1 } < seconds { 1 }));
    assert(!(milliseconds { 42 } < milliseconds { 42 }));
    assert(!(microseconds { 143 } < microseconds { 143 }));
    assert(!(seconds { 1 } < milliseconds { 1'000 }));

    assert(seconds { 0 } <= seconds { 1 });
    assert(milliseconds { 999 } <= seconds { 1 });
    assert(milliseconds { 1000 } <= seconds { 1 });
    assert(milliseconds { 42 } <= milliseconds { 143 });
    assert(microseconds { 143 } <= microseconds { 1'000 });
    assert(seconds { 1 } <= seconds { 1 });

    assert(!(seconds { 0 } > seconds { 1 }));
    assert(!(milliseconds { 999 } > seconds { 1 }));
    assert(!(milliseconds { 42 } > milliseconds { 143 }));
    assert(!(microseconds { 143 } > microseconds { 1'000 }));

    assert(milliseconds { 1'000 } > milliseconds { 42 });
    assert(microseconds { 144 } > microseconds { 143 });
    assert(seconds { 1 } > milliseconds { 999 });

    assert(!(seconds { 0 } >= seconds { 1 }));
    assert(!(milliseconds { 999 } >= seconds { 1 }));
    assert(!(milliseconds { 42 } >= milliseconds { 143 }));
    assert(!(microseconds { 143 } >= microseconds { 1'000 }));

    assert(milliseconds { 1'000 } >= milliseconds { 42 });
    assert(microseconds { 144 } >= microseconds { 143 });
    assert(seconds { 1 } >= milliseconds { 1'000 });

    assert(etl::chrono::abs(minutes { -10 }) == minutes { 10 });
    assert(etl::chrono::abs(minutes { -143 }) == minutes { 143 });

    using etl::chrono::duration_cast;
    assert(duration_cast<microseconds>(milliseconds { 1 }).count() == 1'000);
    assert(duration_cast<seconds>(milliseconds { 1'000 }).count() == 1);
    assert(duration_cast<microseconds>(milliseconds { 99 }).count() == 99'000);

    {
        using namespace etl::literals;

        auto const h = 1_h;
        assert(h.count() == etl::chrono::hours { 1 }.count());

        auto const m = 1_min;
        assert(m.count() == etl::chrono::minutes { 1 }.count());

        auto const s = 1_s;
        assert(s.count() == etl::chrono::seconds { 1 }.count());

        auto const ms = 1_ms;
        assert(ms.count() == etl::chrono::milliseconds { 1 }.count());

        auto const us = 10_us;
        assert(us.count() == etl::chrono::microseconds { 10 }.count());

        auto const ns = 10_ns;
        assert(ns.count() == etl::chrono::nanoseconds { 10 }.count());
    }

    return true;
}

constexpr auto test_all() -> bool
{
    assert(test<etl::int8_t>());
    assert(test<etl::int16_t>());
    assert(test<etl::int32_t>());
    assert(test<float>());

#if not defined(TETL_WORKAROUND_AVR_BROKEN_TESTS)
    assert(test<etl::int64_t>());
    assert(test<double>());
#endif

    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}