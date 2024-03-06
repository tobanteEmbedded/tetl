// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/cstdint.hpp>
#include <etl/functional.hpp>
#include <etl/vector.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    // find match
    {
        auto src  = etl::array {T(0), T(0), T(0), T(1), T(2), T(3)};
        auto dest = etl::array {T(1), T(2), T(3)};
        auto* res = etl::search(begin(src), end(src), begin(dest), end(dest));
        assert(*res == T(1));
    }

    // no match
    {
        auto src  = etl::array {T(0), T(0), T(0), T(0), T(2), T(3)};
        auto dest = etl::array {T(1), T(2), T(3)};
        auto* res = etl::search(begin(src), end(src), begin(dest), end(dest));
        assert(res == end(src));
    }

    // match range empty
    {
        auto src  = etl::array {T(0), T(0), T(0), T(0), T(2), T(3)};
        auto dest = etl::static_vector<T, 0> {};
        auto* res = etl::search(begin(src), end(src), begin(dest), end(dest));
        assert(res == begin(src));
    }

    // searcher
    {
        auto src = etl::array {T(0), T(0), T(0), T(1), T(2), T(3)};

        auto t1 = etl::array {T(1), T(2), T(3)};
        auto s1 = etl::default_searcher(t1.begin(), t1.end());
        assert(*etl::search(src.begin(), src.end(), s1) == T(1));

        auto t2 = etl::static_vector<T, 0> {};
        auto s2 = etl::default_searcher(t2.begin(), t2.end());
        assert(etl::search(src.begin(), src.end(), s2) == begin(src));
    }

    // empty range
    {
        auto src  = etl::static_vector<T, 2> {};
        auto* res = etl::search_n(begin(src), end(src), 3, T(0));
        assert((res == end(src)));
    }

    // zero or negative count
    {
        auto src = etl::array {T(0), T(0), T(0), T(1), T(2), T(3)};
        assert((etl::search_n(begin(src), end(src), 0, T(0)) == begin(src)));
    }

    // no match
    {
        auto src  = etl::array {T(0), T(0), T(0), T(1), T(2), T(3)};
        auto* res = etl::search_n(begin(src), end(src), 3, T(42));
        assert((res == end(src)));
    }

    // find match
    {
        auto src  = etl::array {T(0), T(0), T(0), T(1), T(2), T(3)};
        auto* res = etl::search_n(begin(src), end(src), 3, T(0));
        assert((res == begin(src)));
        assert((*res == T(0)));
    }

    // cppreference.com example
    {
        etl::array<T, 12> v {1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4};
        etl::array<T, 3> t1 {1, 2, 3};

        auto* result = etl::find_end(begin(v), end(v), begin(t1), end(t1));
        assert(etl::distance(begin(v), result) == 8);

        etl::array<T, 3> t2 {4, 5, 6};
        result = etl::find_end(begin(v), end(v), begin(t2), end(t2));
        assert(result == end(v));
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
