/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/iterator.hpp"

#include "etl/cstdint.hpp"
#include "etl/vector.hpp"

#include "testing/testing.hpp"

template <typename T>
auto test() -> bool
{
    // back_inserter
    { // "insert rvalue"
        {
            auto vec  = etl::static_vector<T, 5> {};
            auto iter = etl::back_inserter(vec);
            assert(vec.size() == 0);
            iter = T { 1 };
            assert(vec.size() == 1);
        }

        // "insert lvalue"
        {
            auto vec  = etl::static_vector<T, 5> {};
            auto iter = etl::back_inserter(vec);
            assert(vec.size() == 0);
            auto const val = T { 42 };
            iter           = val;
            assert(vec.size() == 1);
        }

        // "increment/decrement/dereference should not change state (no-op)"
        {
            auto vec  = etl::static_vector<T, 5> {};
            auto iter = etl::back_inserter(vec);
            assert(vec.size() == 0);
            auto const val = T { 42 };
            iter           = val;
            assert(vec.size() == 1);
            assert(&++iter == &iter); // NOLINT
            assert(vec.size() == 1);
            *iter;
            assert(vec.size() == 1);
        }

        // front_inserter
        {
            auto vec  = etl::static_vector<T, 5> {};
            auto iter = etl::front_inserter(vec);
            assert(&++iter == &iter);    // NOLINT
            assert(&++iter == &(*iter)); // NOLINT
        }
    }

    return true;
}

auto test_all() -> bool
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

    // TODO: [tobi] Enable constexpr tests
    // static_assert(test_all());
    return 0;
}