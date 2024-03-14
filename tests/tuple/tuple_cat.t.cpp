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
    ASSERT(etl::same_as<decltype(etl::tuple_cat(etl::tuple<T>{})), etl::tuple<T>>);
    ASSERT(etl::same_as<decltype(etl::tuple_cat(etl::tuple<T, float>{})), etl::tuple<T, float>>);

    ASSERT(etl::same_as<
           decltype(etl::tuple_cat(etl::tuple<T, float>{}, etl::tuple<T, float>{})),
           etl::tuple<T, float, T, float>>);

    auto t = etl::tuple_cat(etl::tuple{T(42), 143.0}, etl::array<T, 2>{});
    ASSERT(etl::same_as<decltype(t), etl::tuple<T, double, T, T>>);

    return true;
}

constexpr auto test_all() -> bool
{
    ASSERT(test<etl::uint8_t>());
    ASSERT(test<etl::int8_t>());
    ASSERT(test<etl::uint16_t>());
    ASSERT(test<etl::int16_t>());
    ASSERT(test<etl::uint32_t>());
    ASSERT(test<etl::int32_t>());
    ASSERT(test<etl::uint64_t>());
    ASSERT(test<etl::int64_t>());
    ASSERT(test<float>());
    ASSERT(test<double>());
    ASSERT(test<long double>());

    return true;
}

} // namespace

auto main() -> int
{
    ASSERT(test_all());
    static_assert(test_all());
    return 0;
}
