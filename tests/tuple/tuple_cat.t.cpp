// SPDX-License-Identifier: BSL-1.0

#include <etl/tuple.hpp>

#include <etl/array.hpp>
#include <etl/concepts.hpp>
#include <etl/cstdint.hpp>
#include <etl/utility.hpp>

#include "testing/testing.hpp"

namespace {

template <typename T>
constexpr auto test() -> bool
{
    CHECK_SAME_TYPE(decltype(etl::tuple_cat(etl::tuple<T>{})), etl::tuple<T>);
    CHECK_SAME_TYPE(decltype(etl::tuple_cat(etl::tuple<T, float>{})), etl::tuple<T, float>);
    CHECK_SAME_TYPE(decltype(etl::tuple_cat(etl::tuple<T, float>{}, etl::tuple<T, float>{})), etl::tuple<T, float, T, float>);

    auto t = etl::tuple_cat(etl::tuple{T(42), 143.0}, etl::array<T, 2>{});
    CHECK_SAME_TYPE(decltype(t), etl::tuple<T, double, T, T>);

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
    CHECK(test<long double>());

    return true;
}

} // namespace

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
