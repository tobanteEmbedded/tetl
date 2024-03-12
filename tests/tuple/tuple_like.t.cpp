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
    ASSERT(etl::tuple_like<etl::array<T, 1>>);
    ASSERT(etl::tuple_like<etl::array<T, 2>>);
    ASSERT(etl::tuple_like<etl::array<T, 5>>);

    ASSERT(etl::tuple_like<etl::complex<T>>);
    ASSERT(etl::tuple_like<etl::pair<T, double>>);

    ASSERT(etl::tuple_like<etl::tuple<T>>);
    ASSERT(etl::tuple_like<etl::tuple<int, T>>);
    ASSERT(etl::tuple_like<etl::tuple<int, T, char const*>>);

    ASSERT(etl::pair_like<etl::complex<T>>);
    ASSERT(etl::pair_like<etl::array<T, 2>>);
    ASSERT(etl::pair_like<etl::pair<T, double>>);
    ASSERT(etl::pair_like<etl::tuple<int, T>>);

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
