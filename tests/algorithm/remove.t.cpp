// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/cstdint.hpp>
#include <etl/iterator.hpp>
#include <etl/vector.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    // empty range
    {
        auto data = etl::static_vector<T, 4>{};
        auto* res = etl::remove(begin(data), end(data), T{1});
        CHECK(res == end(data));
        CHECK(data.empty());
    }

    // found
    {
        auto data = etl::static_vector<T, 4>{};
        data.push_back(T{1});
        data.push_back(T{0});
        data.push_back(T{0});
        data.push_back(T{0});

        auto* res = etl::remove(begin(data), end(data), T{1});
        CHECK(res == end(data) - 1);
        CHECK(data[0] == 0);
    }
    // empty range
    {
        auto s = etl::static_vector<T, 4>{};
        auto d = etl::static_vector<T, 4>{};
        etl::remove_copy(begin(s), end(s), etl::back_inserter(d), T(1));
        CHECK(d.empty());
    }

    // range
    {
        auto s = etl::array{T(1), T(2), T(3), T(4)};
        auto d = etl::static_vector<T, 4>{};
        etl::remove_copy(begin(s), end(s), etl::back_inserter(d), T(1));
        CHECK_FALSE(d.empty());
        CHECK(d.size() == 3);
        CHECK(etl::all_of(begin(d), end(d), [](auto v) { return v > T(1); }));
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
