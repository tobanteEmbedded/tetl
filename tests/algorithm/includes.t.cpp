// SPDX-License-Identifier: BSL-1.0

#include "etl/algorithm.hpp"

#include "etl/array.hpp"
#include "etl/cctype.hpp"
#include "etl/cstdint.hpp"

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{

    {
        auto const v1 = etl::array {'a', 'b', 'c', 'f', 'h', 'x'};
        auto const v2 = etl::array {'a', 'b', 'c'};
        auto const v3 = etl::array {'a', 'c'};
        auto const v4 = etl::array {'a', 'a', 'b'};
        auto const v5 = etl::array {'g'};
        auto const v6 = etl::array {'a', 'c', 'g'};
        auto const v7 = etl::array {'A', 'B', 'C'};

        auto noCase = [](char a, char b) { return etl::tolower(a) < etl::tolower(b); };

        assert(etl::includes(begin(v1), end(v1), v2.begin(), v2.end()));
        assert(etl::includes(begin(v1), end(v1), v3.begin(), v3.end()));
        assert(etl::includes(begin(v1), end(v1), v7.begin(), v7.end(), noCase));

        assert(!(etl::includes(begin(v1), end(v1), v4.begin(), v4.end())));
        assert(!(etl::includes(begin(v1), end(v1), v5.begin(), v5.end())));
        assert(!(etl::includes(begin(v1), end(v1), v6.begin(), v6.end())));
    }

    {
        auto const v1 = etl::array {T(1), T(2), T(3), T(6), T(8), T(24)};
        auto const v2 = etl::array {T(1), T(2), T(3)};
        auto const v3 = etl::array {T(1), T(3)};
        auto const v4 = etl::array {T(1), T(1), T(2)};
        auto const v5 = etl::array {T(7)};
        auto const v6 = etl::array {T(1), T(3), T(7)};

        assert(etl::includes(begin(v1), end(v1), v2.begin(), v2.end()));
        assert(etl::includes(begin(v1), end(v1), v3.begin(), v3.end()));

        assert(!(etl::includes(begin(v1), end(v1), v4.begin(), v4.end())));
        assert(!(etl::includes(begin(v1), end(v1), v5.begin(), v5.end())));
        assert(!(etl::includes(begin(v1), end(v1), v6.begin(), v6.end())));
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
