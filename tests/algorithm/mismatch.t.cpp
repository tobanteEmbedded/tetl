// SPDX-License-Identifier: BSL-1.0

#include "etl/algorithm.hpp"

#include "etl/array.hpp"
#include "etl/cstdint.hpp"
#include "etl/iterator.hpp"

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    // first1,last1,first2
    {
        auto lhs    = etl::array {T(0), T(1), T(2)};
        auto rhs    = etl::array {T(0), T(1), T(3)};
        auto result = etl::mismatch(begin(lhs), end(lhs), begin(rhs));
        assert(*result.first == T(2));
        assert(*result.second == T(3));
    }

    // first1,last1,first2,last2
    {
        auto lhs    = etl::array {T(0), T(1), T(2)};
        auto rhs    = etl::array {T(0), T(1), T(4)};
        auto result = etl::mismatch(begin(lhs), end(lhs), begin(rhs), end(rhs));
        assert(*result.first == T(2));
        assert(*result.second == T(4));
    }
    return true;
}

constexpr auto test_all() -> bool
{
    assert(test<etl::uint8_t>());
    assert(test<etl::int8_t>());
    assert(test<etl::uint16_t>());
    assert(test<etl::int16_t>());
    assert(test<etl::uint32_t>());
    assert(test<etl::int32_t>());
    assert(test<etl::uint64_t>());
    assert(test<etl::int64_t>());
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
