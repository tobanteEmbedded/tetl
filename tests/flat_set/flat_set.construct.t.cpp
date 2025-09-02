// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/flat_set.hpp>
    #include <etl/functional.hpp>
    #include <etl/iterator.hpp>
    #include <etl/vector.hpp>
#endif

namespace {

template <typename T, typename Compare>
constexpr auto test_less() -> bool
{
    using vector   = etl::static_vector<T, 4>;
    using flat_set = etl::flat_set<T, vector, Compare>;

    // default
    {
        auto empty = flat_set{};
        CHECK(empty.empty());
        CHECK(empty.begin() == empty.end());
        CHECK(empty.rbegin() == empty.rend());
    }

    // from container
    {
        auto empty = flat_set{vector{}};
        CHECK(empty.empty());
        CHECK(empty.begin() == empty.end());
        CHECK(empty.rbegin() == empty.rend());

        auto noduplicates = flat_set{vector({T(0), T(2), T(3), T(1)})};
        CHECK(noduplicates.size() == 4);
        CHECK(*noduplicates.begin() == T(0));
        CHECK(*etl::prev(noduplicates.end()) == T(3));

        auto withduplicates = flat_set{vector({T(0), T(2), T(3), T(2)})};
        CHECK(withduplicates.size() == 3);
        CHECK(*withduplicates.begin() == T(0));
        CHECK(*etl::prev(withduplicates.end()) == T(3));
    }

    // from container sorted_unique
    {
        auto empty = flat_set{etl::sorted_unique, vector{}};
        CHECK(empty.empty());
        CHECK(empty.begin() == empty.end());
        CHECK(empty.rbegin() == empty.rend());

        auto set = flat_set{etl::sorted_unique, vector({T(0), T(1), T(2), T(3)})};
        CHECK(set.size() == 4);
        CHECK(*set.begin() == T(0));
        CHECK(*etl::prev(set.end()) == T(3));
    }

    // from iterators
    {
        auto emptyVec = vector{};
        auto empty    = flat_set{etl::sorted_unique, emptyVec.begin(), emptyVec.end()};
        CHECK(empty.empty());
        CHECK(empty.begin() == empty.end());
        CHECK(empty.rbegin() == empty.rend());

        auto vec1         = vector({T(0), T(2), T(3), T(1)});
        auto noduplicates = flat_set{vec1.begin(), vec1.end()};
        CHECK(noduplicates.size() == 4);
        CHECK(*noduplicates.begin() == T(0));
        CHECK(*etl::prev(noduplicates.end()) == T(3));

        auto vec2           = vector({T(0), T(2), T(3), T(2)});
        auto withduplicates = flat_set{vec2.begin(), vec2.end()};
        CHECK(withduplicates.size() == 3);
        CHECK(*withduplicates.begin() == T(0));
        CHECK(*etl::prev(withduplicates.end()) == T(3));
    }

    // from iterators sorted_unique
    {
        auto emptyVec = vector{};
        auto empty    = flat_set{etl::sorted_unique, emptyVec.begin(), emptyVec.end()};
        CHECK(empty.empty());
        CHECK(empty.begin() == empty.end());
        CHECK(empty.rbegin() == empty.rend());

        auto vec = vector({T(0), T(1), T(2), T(3)});
        auto set = flat_set{etl::sorted_unique, vec.begin(), vec.end()};
        CHECK(set.size() == 4);
        CHECK(*set.begin() == T(0));
        CHECK(*etl::prev(set.end()) == T(3));
    }

    return true;
}

template <typename T, typename Compare>
constexpr auto test_greater() -> bool
{
    using vector   = etl::static_vector<T, 4>;
    using flat_set = etl::flat_set<T, vector, Compare>;

    // default
    {
        auto empty = flat_set{};
        CHECK(empty.empty());
        CHECK(empty.begin() == empty.end());
        CHECK(empty.rbegin() == empty.rend());
    }

    // from container
    {
        auto empty = flat_set{vector{}};
        CHECK(empty.empty());
        CHECK(empty.begin() == empty.end());
        CHECK(empty.rbegin() == empty.rend());

        auto noduplicates = flat_set{vector({T(0), T(2), T(3), T(1)})};
        CHECK(noduplicates.size() == 4);
        CHECK(*noduplicates.begin() == T(3));
        CHECK(*etl::prev(noduplicates.end()) == T(0));

        auto withduplicates = flat_set{vector({T(0), T(2), T(3), T(2)})};
        CHECK(withduplicates.size() == 3);
        CHECK(*withduplicates.begin() == T(3));
        CHECK(*etl::prev(withduplicates.end()) == T(0));
    }

    // from container sorted_unique
    {
        auto empty = flat_set{etl::sorted_unique, vector{}};
        CHECK(empty.empty());
        CHECK(empty.begin() == empty.end());
        CHECK(empty.rbegin() == empty.rend());

        auto set = flat_set{etl::sorted_unique, vector({T(3), T(2), T(1), T(0)})};
        CHECK(set.size() == 4);
        CHECK(*set.begin() == T(3));
        CHECK(*etl::prev(set.end()) == T(0));
    }

    // from iterators
    {
        auto emptyVec = vector{};
        auto empty    = flat_set{etl::sorted_unique, emptyVec.begin(), emptyVec.end()};
        CHECK(empty.empty());
        CHECK(empty.begin() == empty.end());
        CHECK(empty.rbegin() == empty.rend());

        auto vec1         = vector({T(0), T(2), T(3), T(1)});
        auto noduplicates = flat_set{vec1.begin(), vec1.end()};
        CHECK(noduplicates.size() == 4);
        CHECK(*noduplicates.begin() == T(3));
        CHECK(*etl::prev(noduplicates.end()) == T(0));

        auto vec2           = vector({T(0), T(2), T(3), T(2)});
        auto withduplicates = flat_set{vec2.begin(), vec2.end()};
        CHECK(withduplicates.size() == 3);
        CHECK(*withduplicates.begin() == T(3));
        CHECK(*etl::prev(withduplicates.end()) == T(0));
    }

    // from iterators sorted_unique
    {
        auto emptyVec = vector{};
        auto empty    = flat_set{etl::sorted_unique, emptyVec.begin(), emptyVec.end()};
        CHECK(empty.empty());
        CHECK(empty.begin() == empty.end());
        CHECK(empty.rbegin() == empty.rend());

        auto vec = vector({T(3), T(2), T(1), T(0)});
        auto set = flat_set{etl::sorted_unique, vec.begin(), vec.end()};
        CHECK(set.size() == 4);
        CHECK(*set.begin() == T(3));
        CHECK(*etl::prev(set.end()) == T(0));
    }

    return true;
}

template <typename T>
constexpr auto test_type() -> bool
{
    struct Less {
        [[nodiscard]] constexpr auto operator()(T lhs, T rhs) const -> bool { return lhs < rhs; }
    };

    struct Greater {
        [[nodiscard]] constexpr auto operator()(T lhs, T rhs) const -> bool { return lhs > rhs; }
    };

    test_less<T, etl::less<T>>();
    test_less<T, etl::less<>>();
    test_less<T, Less>();

    test_greater<T, etl::greater<T>>();
    test_greater<T, etl::greater<>>();
    test_greater<T, Greater>();

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test_type<signed char>());
    CHECK(test_type<signed short>());
    CHECK(test_type<signed int>());
    CHECK(test_type<signed long>());
    CHECK(test_type<signed long long>());

    CHECK(test_type<unsigned char>());
    CHECK(test_type<unsigned short>());
    CHECK(test_type<unsigned int>());
    CHECK(test_type<unsigned long>());
    CHECK(test_type<unsigned long long>());

    CHECK(test_type<char>());
    CHECK(test_type<char8_t>());
    CHECK(test_type<char16_t>());
    CHECK(test_type<char32_t>());
    CHECK(test_type<wchar_t>());

    CHECK(test_type<float>());

    // TODO: break constexpr limits on clang
    // CHECK(test_type<double>());
    // CHECK(test_type<long double>());

    return true;
}

} // namespace

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
