/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/functional.hpp"

#include "etl/algorithm.hpp"
#include "etl/array.hpp"
#include "etl/cstdint.hpp"

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    auto original = etl::array<T, 4> {
        T(4),
        T(3),
        T(2),
        T(1),
    };

    auto sorted = etl::array<etl::reference_wrapper<T>, 4> {
        etl::ref(original[0]),
        etl::ref(original[1]),
        etl::ref(original[2]),
        etl::ref(original[3]),
    };
    etl::sort(begin(sorted), end(sorted));

    assert(original[0] == T(4));
    assert(original[1] == T(3));
    assert(original[2] == T(2));
    assert(original[3] == T(1));

    assert(sorted[0] == T(1));
    assert(sorted[1] == T(2));
    assert(sorted[2] == T(3));
    assert(sorted[3] == T(4));

    for (T& i : original) { i *= T(2); }
    assert(sorted[0] == T(2));
    assert(sorted[1] == T(4));
    assert(sorted[2] == T(6));
    assert(sorted[3] == T(8));

    auto lambda = [](T val) { return val; };
    assert(etl::ref(lambda)(T(0)) == T(0));
    assert(etl::cref(lambda)(T(42)) == T(42));
    assert(etl::ref(etl::ref(lambda))(T(42)) == T(42));
    assert(etl::cref(etl::cref(lambda))(T(42)) == T(42));

    return true;
}

constexpr auto test_all() -> bool
{
    assert(test<etl::int8_t>());
    assert(test<etl::int16_t>());
    assert(test<etl::int32_t>());
    assert(test<etl::int64_t>());
    assert(test<etl::uint8_t>());
    assert(test<etl::uint16_t>());
    assert(test<etl::uint32_t>());
    assert(test<etl::uint64_t>());
    assert(test<float>());
    assert(test<double>());

    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}