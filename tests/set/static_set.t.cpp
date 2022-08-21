/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/set.hpp"

#include "etl/algorithm.hpp"
#include "etl/array.hpp"
#include "etl/cstdint.hpp"
#include "etl/string.hpp"
#include "etl/string_view.hpp"
#include "etl/type_traits.hpp"
#include "etl/utility.hpp"
#include "etl/warning.hpp"

#include "testing/testing.hpp"

template <typename T>
auto test() -> bool // NOLINT(readability-function-size)
{
    {
        using etl::is_same_v;
        using set_t = etl::static_set<T, 16>;

        assert((is_same_v<T, typename set_t::value_type>));
        assert((is_same_v<T&, typename set_t::reference>));
        assert((is_same_v<T const&, typename set_t::const_reference>));
        assert((is_same_v<T*, typename set_t::pointer>));
        assert((is_same_v<T const*, typename set_t::const_pointer>));
        assert((is_same_v<T*, typename set_t::iterator>));
        assert((is_same_v<T const*, typename set_t::const_iterator>));
    }

    {
        using set_t = etl::static_set<T, 16>;

        assert(etl::is_trivial_v<T>);
        assert(etl::is_default_constructible_v<set_t>);
        assert(etl::is_trivially_destructible_v<set_t>);

        struct NonTrivial {
            ~NonTrivial() { } // NOLINT
        };

        using non_trivial_set_t = etl::static_set<NonTrivial, 16>;

        assert(!(etl::is_trivial_v<NonTrivial>));
        assert(!(etl::is_trivially_destructible_v<non_trivial_set_t>));
    }

    // "capacity = 0"
    {
        auto set = etl::static_set<T, 0>();
        assert(set.size() == 0);
        assert(set.max_size() == 0);
        assert(set.empty());
        assert(set.full());
        assert(set.begin() == nullptr);
        assert(etl::as_const(set).begin() == nullptr);
        assert(set.end() == nullptr);
        assert(etl::as_const(set).end() == nullptr);
    }

    // "capacity = 4"
    {
        auto set = etl::static_set<T, 4>();
        assert(set.size() == 0);
        assert(set.max_size() == 4);
        assert(set.empty());
        assert(!(set.full()));
    }

    // "capacity = 16"
    {
        auto set = etl::static_set<T, 16>();
        assert(set.size() == 0);
        assert(set.max_size() == 16);
        assert(set.empty());
        assert(!(set.full()));
    }

    {
        auto data = etl::array { T(2), T(1), T(0), T(1) };
        auto set  = etl::static_set<T, 4>(begin(data), end(data));
        assert(set.size() == 3);
        assert(set.max_size() == 4);
        assert(!(set.empty()));
        assert(!(set.full()));
    }

    {
        auto set = etl::static_set<T, 4>();
        assert(begin(set) == end(set));
        assert(begin(etl::as_const(set)) == end(etl::as_const(set)));
        assert(set.cbegin() == set.cend());

        set.emplace(T(0));
        assert(begin(set) != end(set));
        assert(begin(etl::as_const(set)) != end(etl::as_const(set)));
        assert(cbegin(set) != cend(set));

        for (auto& key : set) { assert(key == 0); }
        etl::for_each(begin(set), end(set), [](auto key) { assert(key == 0); });
    }

    {
        auto set = etl::static_set<T, 4>();
        assert(rbegin(set) == rend(set));
        assert(rbegin(etl::as_const(set)) == rend(etl::as_const(set)));
        assert(set.crbegin() == set.crend());

        set.emplace(T(0));
        assert(rbegin(set) != rend(set));
        assert(rbegin(etl::as_const(set)) != rend(etl::as_const(set)));
        assert(crbegin(set) != crend(set));

        etl::for_each(rbegin(set), rend(set), [](auto key) { assert(key == 0); });

        set.emplace(T(2));
        set.emplace(T(1));
        auto it = set.rbegin();
        assert(*it == T(2));
        *it++;
        assert(*it == T(1));
        *it++;
        assert(*it == T(0));
        *it++;
        assert(it == rend(set));
    }

    {
        auto set = etl::static_set<T, 2>();
        set.emplace(T(1));
        set.emplace(T(4));
        assert(set.full());
        assert(!(set.empty()));

        set.clear();
        assert(set.empty());
        assert(!(set.full()));
    }

    {
        auto set = etl::static_set<T, 4>();

        // first element
        set.emplace(T(1));
        assert(set.contains(1));
        assert(set.size() == 1);
        assert(!(set.empty()));
        assert(!(set.full()));

        // in order, no reordering required
        set.emplace(T(2));
        assert(set.contains(2));
        assert(set.size() == 2);
        assert(!(set.empty()));
        assert(!(set.full()));

        // not in order, reordering required!
        set.emplace(T(0));
        assert(set.contains(0));
        assert(set.size() == 3);
        assert(*set.begin() == 0);
        assert(!(set.empty()));
        assert(!(set.full()));

        // value already in set
        set.emplace(T(0));
        assert(set.contains(0));
        assert(set.size() == 3);
        assert(*set.begin() == 0);
        assert(!(set.empty()));
        assert(!(set.full()));

        // last element
        assert(set.emplace(T(4)).second);
        assert(set.contains(4));
        assert(set.size() == 4);
        assert(*set.begin() == 0);
        assert(set.full());
        assert(!(set.empty()));

        // fails, capacity is reached.
        auto res = set.emplace(T(5));
        assert(res.first == nullptr);
        assert(res.second == false);
        assert(set.size() == 4);
        assert(!(set.contains(5)));

        assert(etl::is_sorted(set.begin(), set.end()));
    }

    {
        auto data = etl::array { T(1), T(2), T(3), T(4) };
        auto set  = etl::static_set<T, 4>(begin(data), end(data));

        assert(set.contains(T(3)));
        assert(set.erase(T(3)) == 1);
        assert(set.size() == 3);
        assert(!(set.contains(T(3))));

        //  assert(set.contains(T(1)));
        //  assert(set.erase(begin(set)) == begin(set) + 1);
        //  assert(set.size() == 2);
        //  assert(!(set.contains(T(1))));

        // assert(set.contains(T(2)));
        // assert(set.erase(begin(set), end(set) - 1) == end(set));
        // assert(set.size() == 1);
        // assert(!(set.contains(T(2))));
    }

    {
        auto set = etl::static_set<T, 4>();
        assert(set.find(0) == end(set));

        set.emplace(T(0));
        assert(set.find(0) != end(set));
        assert(set.find(0) == begin(set));
        assert(set.find(1) == end(set));

        set.emplace(T(1));
        assert(set.find(0) != end(set));
        assert(set.find(1) != end(set));
        assert(set.find(1) == begin(set) + 1);
    }

    {
        auto set = etl::static_set<T, 4>();
        assert(!(set.contains(0)));

        set.emplace(T(0));
        assert(set.contains(0));
        assert(!(set.contains(1)));

        set.emplace(T(1));
        assert(set.contains(0));
        assert(set.contains(1));
    }

    {

        auto set  = etl::static_set<T, 4>();
        auto kCmp = set.key_comp();
        auto vCmp = set.value_comp();

        // Compare functions hould be equal
        assert((kCmp(T(), T()) == vCmp(T(), T())));
        assert((kCmp(T(1), T(1)) == vCmp(T(1), T(1))));
        assert((kCmp(T(1), T(2)) == vCmp(T(1), T(2))));
        assert((kCmp(T(2), T(1)) == vCmp(T(2), T(1))));
    }

    {
        using etl::swap;

        // "empty"
        {
            auto lhs = etl::static_set<T, 4>();
            auto rhs = etl::static_set<T, 4>();
            assert(lhs.empty());
            assert(rhs.empty());

            swap(lhs, rhs);
            assert(lhs.empty());
            assert(rhs.empty());

            rhs.swap(lhs);
            assert(lhs.empty());
            assert(rhs.empty());
        }

        // "same size"
        {
            auto lhsData = etl::array { T(1), T(2), T(3) };
            auto rhsData = etl::array { T(4), T(5), T(6) };
            auto lhs     = etl::static_set<T, 4>(begin(lhsData), end(lhsData));
            auto rhs     = etl::static_set<T, 4>(begin(rhsData), end(rhsData));
            assert(lhs.size() == rhs.size());
            assert(*lhs.begin() == T(1));
            assert(*rhs.begin() == T(4));

            lhs.swap(rhs);
            assert(lhs.size() == rhs.size());
            assert(*lhs.begin() == T(4));
            assert(*rhs.begin() == T(1));

            swap(rhs, lhs);
            assert(lhs.size() == rhs.size());
            assert(*lhs.begin() == T(1));
            assert(*rhs.begin() == T(4));
        }

        // "different size"
        {
            auto lhsData = etl::array { T(1), T(2), T(3) };
            auto rhsData = etl::array { T(4), T(5) };
            auto lhs     = etl::static_set<T, 4>(begin(lhsData), end(lhsData));
            auto rhs     = etl::static_set<T, 4>(begin(rhsData), end(rhsData));
            assert(lhs.size() == 3);
            assert(rhs.size() == 2);
            assert(*lhs.begin() == T(1));
            assert(*rhs.begin() == T(4));

            lhs.swap(rhs);
            assert(lhs.size() == 2);
            assert(rhs.size() == 3);
            assert(*lhs.begin() == T(4));
            assert(*rhs.begin() == T(1));

            swap(rhs, lhs);
            assert(lhs.size() == 3);
            assert(rhs.size() == 2);
            assert(*lhs.begin() == T(1));
            assert(*rhs.begin() == T(4));
        }
    }

    {

        // "empty"
        { auto set = etl::static_set<T, 4> {};
    assert(set.lower_bound(T {}) == set.end());
    assert(set.upper_bound(T {}) == set.end());
}

// "full"
{
    auto data = etl::array { T(1), T(2), T(3), T(4) };
    auto set  = etl::static_set<T, 4> { begin(data), end(data) };
    assert(set.lower_bound(T { 1 }) == set.begin());
    assert((set.upper_bound(T { 1 }) == etl::next(set.begin(), 1)));
}
}

{
    using namespace etl::literals::string_view_literals;
    using str_t = etl::static_string<32>;

    auto data = etl::array { str_t { "test" }, str_t { "test" }, str_t { "test" } };
    auto set  = etl::static_set<str_t, 4> { begin(data), end(data) };
    assert(set.lower_bound("test") == set.begin());
    assert(set.upper_bound("test") == etl::next(set.begin(), 1));
}

{
    // "empty"
    {
        auto lhs = etl::static_set<T, 4>();
        auto rhs = etl::static_set<T, 4>();
        assert(lhs == rhs);
        assert(rhs == lhs);
        assert(etl::as_const(lhs) == etl::as_const(rhs));
        assert(etl::as_const(rhs) == etl::as_const(lhs));

        assert(!(lhs != rhs));
        assert(!(rhs != lhs));
        assert(!(etl::as_const(lhs) != etl::as_const(rhs)));
        assert(!(etl::as_const(rhs) != etl::as_const(lhs)));
    }

    // "equal"
    {
        auto data = etl::array { T(1), T(2), T(3) };
        auto lhs  = etl::static_set<T, 4>(begin(data), end(data));
        auto rhs  = etl::static_set<T, 4>(begin(data), end(data));

        assert(lhs == rhs);
        assert(rhs == lhs);
        assert(etl::as_const(lhs) == etl::as_const(rhs));
        assert(etl::as_const(rhs) == etl::as_const(lhs));

        assert(!(lhs != rhs));
        assert(!(rhs != lhs));
        assert(!(etl::as_const(lhs) != etl::as_const(rhs)));
        assert(!(etl::as_const(rhs) != etl::as_const(lhs)));
    }

    // "not equal"
    {
        auto data = etl::array { T(1), T(2), T(3) };
        auto lhs  = etl::static_set<T, 4>(begin(data), end(data) - 1);
        auto rhs  = etl::static_set<T, 4>(begin(data), end(data));

        assert(lhs != rhs);
        assert(rhs != lhs);
        assert(etl::as_const(lhs) != etl::as_const(rhs));
        assert(etl::as_const(rhs) != etl::as_const(lhs));

        assert(!(lhs == rhs));
        assert(!(rhs == lhs));
        assert(!(etl::as_const(lhs) == etl::as_const(rhs)));
        assert(!(etl::as_const(rhs) == etl::as_const(lhs)));
    }
}

return true;
}

static auto test_all() -> bool
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
