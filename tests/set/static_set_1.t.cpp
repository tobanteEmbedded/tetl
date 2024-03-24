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
        using set_t = etl::static_set<T, 16>;

        CHECK_SAME_TYPE(typename set_t::value_type, T);
        CHECK_SAME_TYPE(typename set_t::reference, T&);
        CHECK_SAME_TYPE(typename set_t::const_reference, T const&);
        CHECK_SAME_TYPE(typename set_t::pointer, T*);
        CHECK_SAME_TYPE(typename set_t::const_pointer, T const*);
        CHECK_SAME_TYPE(typename set_t::iterator, T*);
        CHECK_SAME_TYPE(typename set_t::const_iterator, T const*);
    }

    {
        using set_t = etl::static_set<T, 16>;

        CHECK(etl::is_trivial_v<T>);
        CHECK(etl::is_default_constructible_v<set_t>);
        CHECK(etl::is_trivially_destructible_v<set_t>);

        struct NonTrivial {
            ~NonTrivial() { } // NOLINT
        };

        using non_trivial_set_t = etl::static_set<NonTrivial, 16>;

        CHECK_FALSE(etl::is_trivial_v<NonTrivial>);
        CHECK_FALSE(etl::is_trivially_destructible_v<non_trivial_set_t>);
    }

    // "capacity = 0"
    {
        auto set = etl::static_set<T, 0>();
        CHECK(set.size() == 0);
        CHECK(set.max_size() == 0);
        CHECK(set.empty());
        CHECK(set.full());
        CHECK(set.begin() == nullptr);
        CHECK(etl::as_const(set).begin() == nullptr);
        CHECK(set.end() == nullptr);
        CHECK(etl::as_const(set).end() == nullptr);
    }

    // "capacity = 4"
    {
        auto set = etl::static_set<T, 4>();
        CHECK(set.size() == 0);
        CHECK(set.max_size() == 4);
        CHECK(set.empty());
        CHECK_FALSE(set.full());
    }

    // "capacity = 16"
    {
        auto set = etl::static_set<T, 16>();
        CHECK(set.size() == 0);
        CHECK(set.max_size() == 16);
        CHECK(set.empty());
        CHECK_FALSE(set.full());
    }

    {
        auto data = etl::array{T(2), T(1), T(0), T(1)};
        auto set  = etl::static_set<T, 4>(data.begin(), data.end());
        CHECK(set.size() == 3);
        CHECK(set.max_size() == 4);
        CHECK_FALSE(set.empty());
        CHECK_FALSE(set.full());
    }

    {
        auto set = etl::static_set<T, 4>();
        CHECK(begin(set) == end(set));
        CHECK(begin(etl::as_const(set)) == end(etl::as_const(set)));
        CHECK(set.cbegin() == set.cend());

        set.emplace(T(0));
        CHECK(begin(set) != end(set));
        CHECK(begin(etl::as_const(set)) != end(etl::as_const(set)));
        CHECK(cbegin(set) != cend(set));

        for (auto& key : set) {
            CHECK(key == 0);
        }
        etl::for_each(begin(set), end(set), [](auto key) { CHECK(key == 0); });
    }

    {
        auto set = etl::static_set<T, 4>();
        CHECK(rbegin(set) == rend(set));
        CHECK(rbegin(etl::as_const(set)) == rend(etl::as_const(set)));
        CHECK(set.crbegin() == set.crend());

        set.emplace(T(0));
        CHECK(rbegin(set) != rend(set));
        CHECK(rbegin(etl::as_const(set)) != rend(etl::as_const(set)));
        CHECK(crbegin(set) != crend(set));

        etl::for_each(rbegin(set), rend(set), [](auto key) { CHECK(key == 0); });

        set.emplace(T(2));
        set.emplace(T(1));
        auto it = set.rbegin();
        CHECK(*it == T(2));
        *it++;
        CHECK(*it == T(1));
        *it++;
        CHECK(*it == T(0));
        *it++;
        CHECK(it == rend(set));
    }

    {
        auto set = etl::static_set<T, 2>();
        set.emplace(T(1));
        set.emplace(T(4));
        CHECK(set.full());
        CHECK_FALSE(set.empty());

        set.clear();
        CHECK(set.empty());
        CHECK_FALSE(set.full());
    }

    {
        auto set = etl::static_set<T, 4>();

        // first element
        set.emplace(T(1));
        CHECK(set.contains(1));
        CHECK(set.size() == 1);
        CHECK_FALSE(set.empty());
        CHECK_FALSE(set.full());

        // in order, no reordering required
        set.emplace(T(2));
        CHECK(set.contains(2));
        CHECK(set.size() == 2);
        CHECK_FALSE(set.empty());
        CHECK_FALSE(set.full());

        // not in order, reordering required!
        set.emplace(T(0));
        CHECK(set.contains(0));
        CHECK(set.size() == 3);
        CHECK(*set.begin() == 0);
        CHECK_FALSE(set.empty());
        CHECK_FALSE(set.full());

        // value already in set
        set.emplace(T(0));
        CHECK(set.contains(0));
        CHECK(set.size() == 3);
        CHECK(*set.begin() == 0);
        CHECK_FALSE(set.empty());
        CHECK_FALSE(set.full());

        // last element
        CHECK(set.emplace(T(4)).second);
        CHECK(set.contains(4));
        CHECK(set.size() == 4);
        CHECK(*set.begin() == 0);
        CHECK(set.full());
        CHECK_FALSE(set.empty());

        // fails, capacity is reached.
        auto res = set.emplace(T(5));
        CHECK(res.first == nullptr);
        CHECK(res.second == false);
        CHECK(set.size() == 4);
        CHECK_FALSE(set.contains(5));

        CHECK(etl::is_sorted(set.begin(), set.end()));
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
