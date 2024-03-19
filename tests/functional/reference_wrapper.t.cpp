// SPDX-License-Identifier: BSL-1.0

#include <etl/functional.hpp>

#include <etl/algorithm.hpp>
#include <etl/array.hpp>
#include <etl/cstdint.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    auto original = etl::array<T, 4>{
        T(4),
        T(3),
        T(2),
        T(1),
    };

    auto sorted = etl::array<etl::reference_wrapper<T>, 4>{
        etl::ref(original[0]),
        etl::ref(original[1]),
        etl::ref(original[2]),
        etl::ref(original[3]),
    };
    etl::sort(begin(sorted), end(sorted));

    CHECK(original[0] == T(4));
    CHECK(original[1] == T(3));
    CHECK(original[2] == T(2));
    CHECK(original[3] == T(1));

    CHECK(sorted[0] == T(1));
    CHECK(sorted[1] == T(2));
    CHECK(sorted[2] == T(3));
    CHECK(sorted[3] == T(4));

    for (T& i : original) {
        i *= T(2);
    }
    CHECK(sorted[0] == T(2));
    CHECK(sorted[1] == T(4));
    CHECK(sorted[2] == T(6));
    CHECK(sorted[3] == T(8));

    auto lambda = [](T val) { return val; };
    CHECK(etl::ref(lambda)(T(0)) == T(0));
    CHECK(etl::cref(lambda)(T(42)) == T(42));
    CHECK(etl::ref(etl::ref(lambda))(T(42)) == T(42));
    CHECK(etl::cref(etl::cref(lambda))(T(42)) == T(42));

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test<etl::int8_t>());
    CHECK(test<etl::int16_t>());
    CHECK(test<etl::int32_t>());
    CHECK(test<etl::int64_t>());
    CHECK(test<etl::uint8_t>());
    CHECK(test<etl::uint16_t>());
    CHECK(test<etl::uint32_t>());
    CHECK(test<etl::uint64_t>());
    CHECK(test<float>());
    CHECK(test<double>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
