// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/cstdint.hpp>
#include <etl/iterator.hpp>
#include <etl/numeric.hpp>

#include "testing/iterator_types.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    auto src = etl::array<T, 4>{};
    etl::iota(begin(src), end(src), T{0});

    CHECK(etl::count(begin(src), end(src), T{0}) == 1);
    CHECK(etl::count(begin(src), end(src), T{1}) == 1);
    CHECK(etl::count(begin(src), end(src), T{2}) == 1);
    CHECK(etl::count(begin(src), end(src), T{3}) == 1);
    CHECK(etl::count(begin(src), end(src), T{4}) == 0);

    // input iterator
    CHECK(etl::count(InIter(begin(src)), InIter(end(src)), T(0)) == 1);
    // forward iterator
    CHECK(etl::count(FwdIter(begin(src)), FwdIter(end(src)), T(0)) == 1);

    auto p1 = [](auto val) { return val < T{2}; };
    auto p2 = [](auto val) -> bool { return static_cast<int>(val) % 2; };

    CHECK(etl::count_if(begin(src), end(src), p1) == 2);
    CHECK(etl::count_if(begin(src), end(src), p2) == 2);

    // input iterator
    CHECK(etl::count_if(InIter(begin(src)), InIter(end(src)), p1) == 2);
    // forward iterator
    CHECK(etl::count_if(FwdIter(begin(src)), FwdIter(end(src)), p1) == 2);

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
