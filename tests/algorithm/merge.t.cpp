// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/cstdint.hpp>
#include <etl/iterator.hpp>
#include <etl/numeric.hpp>
#include <etl/vector.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    // no overlap
    {
        auto a = etl::array{T(0), T(0), T(0)};
        auto b = etl::array{T(1), T(1), T(1)};
        CHECK((etl::is_sorted(begin(a), end(a))));
        CHECK((etl::is_sorted(begin(b), end(b))));

        auto r = etl::static_vector<T, a.size() + b.size()>{};
        etl::merge(begin(a), end(a), begin(b), end(b), etl::back_inserter(r));
        CHECK((r.size() == 6));
        CHECK((etl::is_sorted(begin(r), end(r))));
    }

    // with overlap
    {
        auto a = etl::array{T(0), T(1), T(2)};
        auto b = etl::array{T(1), T(2), T(3)};
        CHECK((etl::is_sorted(begin(a), end(a))));
        CHECK((etl::is_sorted(begin(b), end(b))));

        auto r = etl::static_vector<T, a.size() + b.size()>{};
        etl::merge(begin(a), end(a), begin(b), end(b), etl::back_inserter(r));
        CHECK((r.size() == 6));
        CHECK((etl::is_sorted(begin(r), end(r))));
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
