// SPDX-License-Identifier: BSL-1.0

#include <etl/tuple.hpp>

#include <etl/array.hpp>
#include <etl/complex.hpp>
#include <etl/cstdint.hpp>
#include <etl/utility.hpp>

#include "testing/testing.hpp"

namespace {

template <typename T>
constexpr auto test() -> bool
{
    CHECK(etl::tuple_like<etl::array<T, 1>>);
    CHECK(etl::tuple_like<etl::array<T, 2>>);
    CHECK(etl::tuple_like<etl::array<T, 5>>);

    CHECK(etl::tuple_like<etl::complex<T>>);
    CHECK(etl::tuple_like<etl::pair<T, double>>);

    CHECK(etl::tuple_like<etl::tuple<T>>);
    CHECK(etl::tuple_like<etl::tuple<int, T>>);
    CHECK(etl::tuple_like<etl::tuple<int, T, char const*>>);

    CHECK(etl::pair_like<etl::complex<T>>);
    CHECK(etl::pair_like<etl::array<T, 2>>);
    CHECK(etl::pair_like<etl::pair<T, double>>);
    CHECK(etl::pair_like<etl::tuple<int, T>>);

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
