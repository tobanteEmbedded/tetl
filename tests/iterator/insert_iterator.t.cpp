// SPDX-License-Identifier: BSL-1.0

#include <etl/iterator.hpp>

#include <etl/cstdint.hpp>
#include <etl/vector.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    // back_inserter
    { // "insert rvalue"
        {
            auto vec  = etl::static_vector<T, 5>{};
            auto iter = etl::back_inserter(vec);
            CHECK(vec.size() == 0);
            iter = T{1};
            CHECK(vec.size() == 1);
        }

        // "insert lvalue"
        {
            auto vec  = etl::static_vector<T, 5>{};
            auto iter = etl::back_inserter(vec);
            CHECK(vec.size() == 0);
            auto const val = T{42};
            iter           = val;
            CHECK(vec.size() == 1);
        }

        // "increment/decrement/dereference should not change state (no-op)"
        {
            auto vec  = etl::static_vector<T, 5>{};
            auto iter = etl::back_inserter(vec);
            CHECK(vec.size() == 0);
            auto const val = T{42};
            iter           = val;
            CHECK(vec.size() == 1);
            CHECK(&++iter == &iter); // NOLINT
            CHECK(vec.size() == 1);
            *iter;
            CHECK(vec.size() == 1);
        }

        // front_inserter
        {
            auto vec  = etl::static_vector<T, 5>{};
            auto iter = etl::front_inserter(vec);
            CHECK(&++iter == &iter);    // NOLINT
            CHECK(&++iter == &(*iter)); // NOLINT
        }
    }

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
