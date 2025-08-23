// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/algorithm.hpp>
    #include <etl/cstddef.hpp>
    #include <etl/iterator.hpp>
    #include <etl/vector.hpp>
#endif

namespace {

template <typename T, etl::size_t Capacity>
struct push_front_vector {
    using value_type = T;
    constexpr auto push_front(T const& val) -> void { vector.insert(vector.begin(), val); }
    constexpr auto push_front(T&& val) -> void { vector.insert(vector.begin(), etl::move(val)); }
    etl::static_vector<T, Capacity> vector;
};

template <typename T>
constexpr auto test() -> bool
{
    // back_inserter
    {
        // "insert rvalue"
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
    }

    // front_inserter
    {
        auto src  = etl::static_vector<T, 5>({T(0), T(1), T(2), T(3), T(4)});
        auto dest = push_front_vector<T, 5>{};
        etl::copy(src.begin(), src.end(), etl::front_inserter(dest));
        CHECK(dest.vector.front() == T(4));
        CHECK(dest.vector.back() == T(0));

        dest.vector.clear();
        etl::move(src.rbegin(), src.rend(), etl::front_inserter(dest));
        CHECK(dest.vector.front() == T(0));
        CHECK(dest.vector.back() == T(4));
    }

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test<signed char>());
    CHECK(test<signed short>());
    CHECK(test<signed int>());
    CHECK(test<signed long>());
    CHECK(test<signed long long>());

    CHECK(test<unsigned char>());
    CHECK(test<unsigned short>());
    CHECK(test<unsigned int>());
    CHECK(test<unsigned long>());
    CHECK(test<unsigned long long>());

    CHECK(test<char>());
    CHECK(test<char8_t>());
    CHECK(test<char16_t>());
    CHECK(test<char32_t>());
    CHECK(test<wchar_t>());

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
