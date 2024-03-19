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
    // c array
    {
        T source[4] = {};
        etl::fill(etl::begin(source), etl::end(source), T{42});

        auto const all42
            = etl::all_of(etl::begin(source), etl::end(source), [](auto const& val) { return val == T{42}; });

        CHECK(all42);
    }

    // etl::array
    {
        auto source = etl::array<T, 4>{};
        etl::fill(begin(source), end(source), T{42});

        auto const all42 = etl::all_of(begin(source), end(source), [](auto const& val) { return val == T{42}; });

        CHECK(all42);
    }

    // c array
    {
        T t[4] = {};
        etl::fill_n(etl::begin(t), 4, T{42});
        CHECK(etl::all_of(etl::begin(t), etl::end(t), [](auto v) { return v == T(42); }));
    }

    // etl::array
    {
        auto tc0 = etl::array<T, 4>{};
        CHECK(etl::fill_n(begin(tc0), 0, T{42}) == begin(tc0));

        auto t1 = etl::array<T, 4>{};
        CHECK(etl::fill_n(begin(t1), 4, T{42}) == end(t1));
        CHECK(etl::all_of(begin(t1), end(t1), [](auto v) { return v == T(42); }));

        auto tc2   = etl::array<T, 4>{};
        auto* res2 = etl::fill_n(begin(tc2), 2, T{42});
        CHECK(res2 != begin(tc2));
        CHECK(res2 != end(tc2));
        CHECK(tc2[0] == T(42));
        CHECK(tc2[1] == T(42));
        CHECK(tc2[2] == T(0));
        CHECK(tc2[3] == T(0));
    }

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test<etl::uint8_t>());
    CHECK(test<etl::int8_t>());
    CHECK(test<etl::uint16_t>());
    CHECK(test<etl::int16_t>());
    CHECK(test<etl::uint32_t>());
    CHECK(test<etl::int32_t>());
    CHECK(test<etl::uint64_t>());
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
