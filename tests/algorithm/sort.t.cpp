/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/algorithm.hpp"

#include "etl/array.hpp"
#include "etl/cstdint.hpp"
#include "etl/functional.hpp"
#include "etl/iterator.hpp"
#include "etl/numeric.hpp"
#include "etl/vector.hpp"

#include "testing.hpp"

template <typename T>
constexpr auto test() -> bool
{

    // already sorted
    {
        auto src = etl::array<T, 4> {};
        src[0]   = T { 1 };
        src[1]   = T { 2 };
        src[2]   = T { 3 };
        src[3]   = T { 4 };

        etl::sort(begin(src), end(src), etl::less<T> {});
        assert(src[0] == T { 1 });
        assert(src[1] == T { 2 });
        assert(src[2] == T { 3 });
        assert(src[3] == T { 4 });
    }

    // reversed
    {
        auto src = etl::array<T, 4> {};
        src[0]   = T { 4 };
        src[1]   = T { 3 };
        src[2]   = T { 2 };
        src[3]   = T { 1 };

        etl::sort(begin(src), end(src));
        assert(src[0] == T { 1 });
        assert(src[1] == T { 2 });
        assert(src[2] == T { 3 });
        assert(src[3] == T { 4 });
    }

    // custom compare
    {
        auto src = etl::array<T, 4> {};
        src[0]   = T { 1 };
        src[1]   = T { 1 };
        src[2]   = T { 56 };
        src[3]   = T { 42 };

        etl::sort(begin(src), end(src),
            [](auto const& lhs, auto const& rhs) { return lhs > rhs; });
        assert(src[0] == T { 56 });
        assert(src[1] == T { 42 });
        assert(src[2] == T { 1 });
        assert(src[3] == T { 1 });
    }

    // empty range
    {
        auto src = etl::static_vector<T, 4> {};
        assert(src.empty());
        etl::stable_sort(begin(src), end(src), etl::less<T> {});
        assert(src.empty());
    }

    // already sorted
    {
        auto src = etl::array<T, 4> { T { 1 }, T { 2 }, T { 3 }, T { 4 } };
        etl::stable_sort(begin(src), end(src));
        assert(src[0] == T { 1 });
        assert(src[1] == T { 2 });
        assert(src[2] == T { 3 });
        assert(src[3] == T { 4 });
    }

    // reversed
    {
        auto src = etl::array<T, 4> { T { 4 }, T { 3 }, T { 2 }, T { 1 } };
        etl::stable_sort(begin(src), end(src));
        assert(src[0] == T { 1 });
        assert(src[1] == T { 2 });
        assert(src[2] == T { 3 });
        assert(src[3] == T { 4 });
    }

    // empty range
    {
        auto src = etl::static_vector<T, 4> {};
        assert(src.empty());
        etl::partial_sort(begin(src), begin(src), end(src), etl::less<T> {});
        assert(src.empty());
    }

    // already sorted
    {
        auto src = etl::array<T, 4> { T { 1 }, T { 2 }, T { 3 }, T { 4 } };
        etl::partial_sort(begin(src), begin(src) + 2, end(src));
        assert(src[0] == T { 1 });
        assert(src[1] == T { 2 });
    }

    // reversed
    {
        auto src = etl::array<T, 4> { T { 4 }, T { 3 }, T { 2 }, T { 1 } };
        etl::partial_sort(begin(src), begin(src) + 2, end(src));
        assert(src[0] == T { 1 });
        assert(src[1] == T { 2 });
    }

    // empty range
    {
        auto src = etl::static_vector<T, 4> {};
        assert(src.empty());
        etl::nth_element(begin(src), begin(src), end(src));
        assert(src.empty());
    }

    // already sorted
    {
        auto src = etl::array<T, 4> { T { 1 }, T { 2 }, T { 3 }, T { 4 } };
        etl::nth_element(begin(src), begin(src) + 1, end(src), etl::less<> {});
        assert(src[1] == T { 2 });
    }

    // reversed
    {
        auto src = etl::array<T, 4> { T { 4 }, T { 3 }, T { 2 }, T { 1 } };
        etl::nth_element(begin(src), begin(src) + 1, end(src));
        assert(src[1] == T { 2 });
    }

    // already is_sorteded
    {
        auto src = etl::array<T, 4> {
            T { 1 },
            T { 2 },
            T { 3 },
            T { 4 },
        };

        assert(etl::is_sorted(begin(src), end(src), etl::less<T> {}));
    }

    // reversed
    {
        auto src = etl::array<T, 4> {
            T { 4 },
            T { 3 },
            T { 2 },
            T { 1 },
        };

        assert(etl::is_sorted(begin(src), end(src), etl::greater<> {}));
        assert(!etl::is_sorted(begin(src), end(src)));
    }

    // custom compare
    {
        auto src = etl::array<T, 4> {
            T { 1 },
            T { 1 },
            T { 56 },
            T { 42 },
        };

        assert(!(etl::is_sorted(begin(src), end(src), etl::greater<> {})));
    }

    // empty range always returns true
    {
        auto data      = etl::static_vector<T, 1> {};
        auto predicate = [](auto const& val) { return val < T(1); };
        assert(etl::is_partitioned(begin(data), end(data), predicate));
    }

    // true
    {
        auto predicate = [](auto const& val) { return val < T(1); };

        auto test1 = etl::array { T(2), T(2), T(2) };
        assert(etl::is_partitioned(begin(test1), end(test1), predicate));

        auto test2 = etl::array { T(0), T(0), T(2), T(3) };
        assert(etl::is_partitioned(begin(test2), end(test2), predicate));

        auto test3 = etl::array { T(1), T(1), T(2) };
        assert(etl::is_partitioned(begin(test3), end(test3), predicate));
    }

    // false
    {
        auto predicate = [](auto const& val) { return val < T(1); };

        auto test1 = etl::array { T(2), T(0), T(2) };
        assert(!etl::is_partitioned(begin(test1), end(test1), predicate));

        auto test2 = etl::array { T(0), T(0), T(2), T(0) };
        assert(!etl::is_partitioned(begin(test2), end(test2), predicate));
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