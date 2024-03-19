// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/cstdint.hpp>
#include <etl/numeric.hpp>
#include <etl/vector.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    using etl::all_of;

    // c array
    {
        T source[4] = {};
        etl::fill(etl::begin(source), etl::end(source), T{42});

        auto const all42
            = etl::all_of(etl::begin(source), etl::end(source), [](auto const& val) { return val == T{42}; });

        assert(all42);
    }

    // etl::array
    {
        auto source = etl::array<T, 4>{};
        etl::fill(begin(source), end(source), T{42});

        auto const all42 = etl::all_of(begin(source), end(source), [](auto const& val) { return val == T{42}; });

        assert(all42);
    }

    // c array
    {
        using etl::begin;
        using etl::end;

        T t[4] = {};
        etl::fill_n(begin(t), 4, T{42});
        assert(all_of(begin(t), end(t), [](auto v) { return v == T(42); }));
    }

    // etl::array
    {
        auto tc0 = etl::array<T, 4>{};
        assert(etl::fill_n(begin(tc0), 0, T{42}) == begin(tc0));

        auto t1 = etl::array<T, 4>{};
        assert(etl::fill_n(begin(t1), 4, T{42}) == end(t1));
        assert(all_of(begin(t1), end(t1), [](auto v) { return v == T(42); }));

        auto tc2   = etl::array<T, 4>{};
        auto* res2 = etl::fill_n(begin(tc2), 2, T{42});
        assert(res2 != begin(tc2));
        assert(res2 != end(tc2));
        assert(tc2[0] == T(42));
        assert(tc2[1] == T(42));
        assert(tc2[2] == T(0));
        assert(tc2[3] == T(0));
    }

    return true;
}

constexpr auto test_all() -> bool
{
    assert(test<etl::uint8_t>());
    assert(test<etl::int8_t>());
    assert(test<etl::uint16_t>());
    assert(test<etl::int16_t>());
    assert(test<etl::uint32_t>());
    assert(test<etl::int32_t>());
    assert(test<etl::uint64_t>());
    assert(test<etl::int64_t>());
    assert(test<float>());
    assert(test<double>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
