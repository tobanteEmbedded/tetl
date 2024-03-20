// SPDX-License-Identifier: BSL-1.0

#include <etl/set.hpp>

#include <etl/algorithm.hpp>
#include <etl/array.hpp>
#include <etl/cstdint.hpp>
#include <etl/string.hpp>
#include <etl/string_view.hpp>
#include <etl/type_traits.hpp>
#include <etl/utility.hpp>
#include <etl/warning.hpp>

#include "testing/testing.hpp"

template <typename T>
auto test() -> bool // NOLINT(readability-function-size)
{

    {
        auto data = etl::array{T(1), T(2), T(3), T(4)};
        auto set  = etl::static_set<T, 4>(begin(data), end(data));

        CHECK(set.contains(T(3)));
        CHECK(set.erase(T(3)) == 1);
        CHECK(set.size() == 3);
        CHECK_FALSE(set.contains(T(3)));

        // CHECK(set.contains(T(1)));
        // CHECK(set.erase(begin(set)) == begin(set) + 1);
        // CHECK(set.size() == 2);
        // CHECK_FALSE(set.contains(T(1)));

        // CHECK(set.contains(T(2)));
        // CHECK(set.erase(begin(set), end(set) - 1) == end(set));
        // CHECK(set.size() == 1);
        // CHECK_FALSE(set.contains(T(2)));
    }

    {
        auto set = etl::static_set<T, 4>();
        CHECK(set.find(0) == end(set));

        set.emplace(T(0));
        CHECK(set.find(0) != end(set));
        CHECK(set.find(0) == begin(set));
        CHECK(set.find(1) == end(set));

        set.emplace(T(1));
        CHECK(set.find(0) != end(set));
        CHECK(set.find(1) != end(set));
        CHECK(set.find(1) == begin(set) + 1);
    }

    {
        auto set = etl::static_set<T, 4>();
        CHECK_FALSE(set.contains(0));

        set.emplace(T(0));
        CHECK(set.contains(0));
        CHECK_FALSE(set.contains(1));

        set.emplace(T(1));
        CHECK(set.contains(0));
        CHECK(set.contains(1));
    }

    {

        auto set  = etl::static_set<T, 4>();
        auto kCmp = set.key_comp();
        auto vCmp = set.value_comp();

        // Compare functions hould be equal
        CHECK(kCmp(T(), T()) == vCmp(T(), T()));
        CHECK(kCmp(T(1), T(1)) == vCmp(T(1), T(1)));
        CHECK(kCmp(T(1), T(2)) == vCmp(T(1), T(2)));
        CHECK(kCmp(T(2), T(1)) == vCmp(T(2), T(1)));
    }

    // "empty"
    {
        auto lhs = etl::static_set<T, 4>();
        auto rhs = etl::static_set<T, 4>();
        CHECK(lhs.empty());
        CHECK(rhs.empty());

        etl::swap(lhs, rhs);
        CHECK(lhs.empty());
        CHECK(rhs.empty());

        rhs.swap(lhs);
        CHECK(lhs.empty());
        CHECK(rhs.empty());
    }

    // "same size"
    {
        auto lhsData = etl::array{T(1), T(2), T(3)};
        auto rhsData = etl::array{T(4), T(5), T(6)};
        auto lhs     = etl::static_set<T, 4>(begin(lhsData), end(lhsData));
        auto rhs     = etl::static_set<T, 4>(begin(rhsData), end(rhsData));
        CHECK(lhs.size() == rhs.size());
        CHECK(*lhs.begin() == T(1));
        CHECK(*rhs.begin() == T(4));

        lhs.swap(rhs);
        CHECK(lhs.size() == rhs.size());
        CHECK(*lhs.begin() == T(4));
        CHECK(*rhs.begin() == T(1));

        swap(rhs, lhs);
        CHECK(lhs.size() == rhs.size());
        CHECK(*lhs.begin() == T(1));
        CHECK(*rhs.begin() == T(4));
    }

    // "different size"
    {
        auto lhsData = etl::array{T(1), T(2), T(3)};
        auto rhsData = etl::array{T(4), T(5)};
        auto lhs     = etl::static_set<T, 4>(begin(lhsData), end(lhsData));
        auto rhs     = etl::static_set<T, 4>(begin(rhsData), end(rhsData));
        CHECK(lhs.size() == 3);
        CHECK(rhs.size() == 2);
        CHECK(*lhs.begin() == T(1));
        CHECK(*rhs.begin() == T(4));

        lhs.swap(rhs);
        CHECK(lhs.size() == 2);
        CHECK(rhs.size() == 3);
        CHECK(*lhs.begin() == T(4));
        CHECK(*rhs.begin() == T(1));

        swap(rhs, lhs);
        CHECK(lhs.size() == 3);
        CHECK(rhs.size() == 2);
        CHECK(*lhs.begin() == T(1));
        CHECK(*rhs.begin() == T(4));
    }

    // "empty"
    {
        auto set = etl::static_set<T, 4>{};
        CHECK(set.lower_bound(T{}) == set.end());
        CHECK(set.upper_bound(T{}) == set.end());
    }

    // "full"
    {
        auto data = etl::array{T(1), T(2), T(3), T(4)};
        auto set  = etl::static_set<T, 4>{begin(data), end(data)};
        CHECK(set.lower_bound(T{1}) == set.begin());
        CHECK(set.upper_bound(T{1}) == etl::next(set.begin(), 1));
    }

    {
        using namespace etl::literals::string_view_literals;
        using str_t = etl::static_string<32>;

        auto data = etl::array{str_t{"test"}, str_t{"test"}, str_t{"test"}};
        auto set  = etl::static_set<str_t, 4>{begin(data), end(data)};
        CHECK(set.lower_bound("test") == set.begin());
        CHECK(set.upper_bound("test") == etl::next(set.begin(), 1));
    }

    {
        // "empty"
        {
            auto lhs = etl::static_set<T, 2>();
            auto rhs = etl::static_set<T, 2>();
            CHECK(lhs == rhs);
            CHECK(rhs == lhs);
            CHECK(etl::as_const(lhs) == etl::as_const(rhs));
            CHECK(etl::as_const(rhs) == etl::as_const(lhs));

            CHECK_FALSE(lhs != rhs);
            CHECK_FALSE(rhs != lhs);
            CHECK_FALSE(etl::as_const(lhs) != etl::as_const(rhs));
            CHECK_FALSE(etl::as_const(rhs) != etl::as_const(lhs));
        }

        // "equal"
        {
            auto data = etl::array{T(1), T(2), T(3)};
            auto lhs  = etl::static_set<T, 4>(begin(data), end(data));
            auto rhs  = etl::static_set<T, 4>(begin(data), end(data));

            CHECK(lhs == rhs);
            CHECK(rhs == lhs);
            CHECK(etl::as_const(lhs) == etl::as_const(rhs));
            CHECK(etl::as_const(rhs) == etl::as_const(lhs));

            CHECK_FALSE(lhs != rhs);
            CHECK_FALSE(rhs != lhs);
            CHECK_FALSE(etl::as_const(lhs) != etl::as_const(rhs));
            CHECK_FALSE(etl::as_const(rhs) != etl::as_const(lhs));
        }

        // "not equal"
        {
            auto data = etl::array{T(1), T(2), T(3)};
            auto lhs  = etl::static_set<T, 4>(begin(data), end(data) - 1);
            auto rhs  = etl::static_set<T, 4>(begin(data), end(data));

            CHECK(lhs != rhs);
            CHECK(rhs != lhs);
            CHECK(etl::as_const(lhs) != etl::as_const(rhs));
            CHECK(etl::as_const(rhs) != etl::as_const(lhs));

            CHECK_FALSE(lhs == rhs);
            CHECK_FALSE(rhs == lhs);
            CHECK_FALSE(etl::as_const(lhs) == etl::as_const(rhs));
            CHECK_FALSE(etl::as_const(rhs) == etl::as_const(lhs));
        }
    }

    return true;
}

static auto test_all() -> bool
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
    CHECK(test_all());

    // TODO: [tobi] Enable constexpr tests
    // static_assert(test_all());
    return 0;
}
