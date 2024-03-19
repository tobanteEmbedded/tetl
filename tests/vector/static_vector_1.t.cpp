// SPDX-License-Identifier: BSL-1.0

#include <etl/vector.hpp>

#include <etl/algorithm.hpp>
#include <etl/cstdint.hpp>
#include <etl/numeric.hpp>
#include <etl/type_traits.hpp>
#include <etl/utility.hpp>

#include "testing/testing.hpp"

using etl::all_of;
using etl::static_vector;

template <typename T>
constexpr auto test_cx() -> bool
{
    {
        using vec_t = static_vector<T, 16>;

        using etl::is_same_v;
        CHECK(is_same_v<T, typename vec_t::value_type>);
        CHECK(is_same_v<T&, typename vec_t::reference>);
        CHECK(is_same_v<T const&, typename vec_t::const_reference>);
        CHECK(is_same_v<T*, typename vec_t::pointer>);
        CHECK(is_same_v<T const*, typename vec_t::const_pointer>);
        CHECK(is_same_v<T*, typename vec_t::iterator>);
        CHECK(is_same_v<T const*, typename vec_t::const_iterator>);
    }

    {
        using vec_t = static_vector<T, 16>;

        CHECK(etl::is_trivial_v<T>);
        CHECK(etl::is_default_constructible_v<vec_t>);
        CHECK(etl::is_trivially_destructible_v<vec_t>);

        struct NonTrivial {
            ~NonTrivial() { } // NOLINT
        };

        using non_trivial_vec_t = static_vector<NonTrivial, 16>;

        CHECK(!(etl::is_trivial_v<NonTrivial>));
        CHECK(!(etl::is_trivially_destructible_v<non_trivial_vec_t>));
    }

    {
        auto zero = static_vector<T, 0>{};
        CHECK(zero.capacity() == zero.max_size());
        CHECK(zero.empty());
        CHECK(zero.size() == 0);
        CHECK(zero.capacity() == 0);
        CHECK(zero.data() == nullptr);
        CHECK(zero.full());
    }

    {
        static_vector<T, 16> lhs{};
        CHECK(lhs.empty());
        CHECK(lhs.size() == 0);
        CHECK(!(lhs.full()));

        CHECK(etl::begin(lhs) == etl::end(lhs));
        CHECK(etl::cbegin(lhs) == etl::cend(lhs));
        CHECK(etl::begin(etl::as_const(lhs)) == etl::end(etl::as_const(lhs)));

        static_vector<T, 16> rhs{};
        CHECK(rhs.empty());
        CHECK(rhs.size() == 0);
        CHECK(!(rhs.full()));

        // comparison empty
        CHECK(lhs == rhs);
        CHECK(rhs == lhs);
        CHECK(!(lhs != rhs));
        CHECK(!(rhs != lhs));
    }

    {
        auto first  = static_vector<T, 4>(4);
        auto second = static_vector<T, 4>{begin(first), end(first)};
        CHECK(first == second);
    }

    {
        static_vector<T, 16> vec(8);
        CHECK(vec.size() == 8);
        CHECK(all_of(begin(vec), end(vec), [](T v) { return v == T(); }));
    }

    {
        static_vector<T, 16> vec(16, T(42));
        CHECK(vec.size() == 16);
        CHECK(all_of(begin(vec), end(vec), [](T v) { return v == T(42); }));
    }

    {
        auto first = static_vector<T, 4>(4);
        static_vector<T, 4> const& second{first};
        CHECK(first == second);
    }

    {
        auto first = static_vector<T, 4>(4);
        static_vector<T, 4> copy{etl::move(first)};

        auto cmp = [](auto val) { return val == T(0); };
        CHECK(all_of(begin(copy), end(copy), cmp));
    }

    {
        auto first = static_vector<T, 4>(4);
        static_vector<T, 4> copy{};
        copy = first;
        CHECK(first == copy);
    }

    {
        auto first = static_vector<T, 4>(4);
        static_vector<T, 4> copy{};
        copy = etl::move(first);

        auto cmp = [](auto val) { return val == T(0); };
        CHECK(all_of(begin(copy), end(copy), cmp));
    }

    {
        etl::static_vector<T, 16> vec{};
        CHECK(vec.empty());
        CHECK(etl::begin(vec) == etl::end(vec));
        CHECK(etl::cbegin(vec) == etl::cend(vec));
        CHECK(etl::begin(etl::as_const(vec)) == etl::end(etl::as_const(vec)));

        vec.push_back(T{2});
        CHECK(!(etl::begin(vec) == etl::end(vec)));
        CHECK(!(etl::cbegin(vec) == etl::cend(vec)));
        CHECK(!(begin(as_const(vec)) == end(as_const(vec))));
    }

    {
        using etl::all_of;

        auto vec = etl::static_vector<T, 4>{};
        CHECK(vec.size() == 0);

        // grow
        vec.resize(etl::size_t{2});
        CHECK(vec.size() == 2);
        CHECK(all_of(begin(vec), end(vec), [](auto x) { return x == T(); }));

        // grow full capacity
        vec.resize(etl::size_t{4});
        CHECK(vec.size() == 4);
        CHECK(all_of(begin(vec), end(vec), [](auto x) { return x == T(); }));

        // same size
        vec.resize(etl::size_t{4});
        CHECK(vec.size() == 4);
        CHECK(all_of(begin(vec), end(vec), [](auto x) { return x == T(); }));

        // shrink
        vec.resize(etl::size_t{2});
        CHECK(vec.size() == 2);
    }

    {
        using etl::all_of;
        using etl::as_const;

        auto a = etl::static_vector<T, 4>{};
        a.assign(4, T{42});
        CHECK(a.size() == 4);
        CHECK(a.front() == 42);
        CHECK(a.back() == 42);
        CHECK(as_const(a).size() == 4);
        CHECK(as_const(a).front() == 42);
        CHECK(as_const(a).back() == 42);
        CHECK(all_of(begin(a), end(a), [](auto val) { return val == T(42); }));

        auto b = etl::static_vector<T, 4>{4};
        b.assign(a.begin(), a.end());
        CHECK(b.size() == 4);
        CHECK(b.front() == 42);
        CHECK(b.back() == 42);
        CHECK(all_of(begin(b), end(b), [](auto val) { return val == T(42); }));
    }

    {
        auto vec = etl::static_vector<T, 4>{};
        CHECK(vec.size() == 0);
        vec.push_back(T(1));
        CHECK(vec.size() == 1);
        vec.pop_back();
        CHECK(vec.size() == 0);
    }

    {
        etl::static_vector<T, 16> vec{{}};
        CHECK(vec.empty());

        vec.push_back(T{1});
        CHECK(!(vec.empty()));
        CHECK(vec.front() == T{1});
        CHECK(vec.back() == T{1});

        vec.push_back(T{2});
        CHECK(!(vec.empty()));
        CHECK(vec.front() == T{1});
        CHECK(vec.back() == T{2});

        CHECK(!(etl::begin(vec) == etl::end(vec)));
        CHECK(!(etl::cbegin(vec) == etl::cend(vec)));
        CHECK(!(begin(as_const(vec)) == end(as_const(vec))));
    }

    {
        auto vec = etl::static_vector<T, 4>{4};
        etl::generate(etl::begin(vec), etl::end(vec), [v = T{}]() mutable { return v += T(1); });

        CHECK(vec.front() == T(1));
        vec.erase(vec.begin());
        CHECK(vec.front() == T(2));
    }

    // method
    {
        auto lhs       = etl::static_vector<T, 4>{4};
        auto generator = [v = T{}]() mutable { return v += T(1); };

        etl::generate(etl::begin(lhs), etl::end(lhs), generator);
        auto rhs = lhs;

        lhs.swap(rhs);
        CHECK(lhs == rhs);
        rhs.swap(lhs);
        CHECK(lhs == rhs);
    }

    // free function
    {
        auto lhs = etl::static_vector<T, 4>{
            {T(1), T(2), T(3), T(4)}
        };
        auto rhs = lhs;
        CHECK(lhs.size() == 4);
        CHECK(rhs.size() == 4);

        using ::etl::swap;
        swap(lhs, rhs);
        CHECK(lhs == rhs);
        swap(rhs, lhs);
        CHECK(lhs == rhs);
    }

    // empty
    {
        auto lhs1       = etl::static_vector<T, 4>{};
        auto const rhs1 = etl::static_vector<T, 4>{};
        CHECK(lhs1 == rhs1);
        CHECK(!(lhs1 != rhs1));

        auto const lhs2 = etl::static_vector<T, 4>();
        auto const rhs2 = etl::static_vector<T, 4>(2);
        CHECK(lhs2 != rhs2);
        CHECK(!(lhs2 == rhs2));

        auto const lhs3 = etl::static_vector<T, 4>(2);
        auto const rhs3 = etl::static_vector<T, 4>();
        CHECK(lhs3 != rhs3);
        CHECK(!(lhs3 == rhs3));
    }

    // with elements
    {
        auto lhs1 = etl::static_vector<T, 4>{};
        lhs1.push_back(T(1));
        lhs1.push_back(T(2));
        auto rhs1 = etl::static_vector<T, 4>{};
        rhs1.push_back(T(1));
        rhs1.push_back(T(2));

        CHECK(lhs1 == rhs1);
        CHECK(!(lhs1 != rhs1));

        auto lhs2 = etl::static_vector<T, 4>{};
        lhs2.push_back(T(1));
        lhs2.push_back(T(2));
        auto rhs2 = etl::static_vector<T, 4>{};
        rhs2.push_back(T(1));
        rhs2.push_back(T(3));

        CHECK(lhs2 != rhs2);
        CHECK(!(lhs2 == rhs2));
    }

    {
        auto lhs       = etl::static_vector<T, 4>();
        auto const rhs = etl::static_vector<T, 4>();
        CHECK(!(lhs < rhs));
        CHECK(!(rhs < lhs));
        CHECK(lhs <= rhs);
        CHECK(rhs <= lhs);
    }

    // full
    {
        auto lhs = etl::static_vector<T, 4>(4);
        etl::iota(begin(lhs), end(lhs), T(0));
        auto rhs = etl::static_vector<T, 4>(4);
        etl::iota(begin(rhs), end(rhs), T(1));

        CHECK(lhs < rhs);
        CHECK(lhs <= rhs);

        CHECK(!(rhs < lhs));
        CHECK(!(rhs <= lhs));
    }

    {
        auto lhs       = etl::static_vector<T, 4>();
        auto const rhs = etl::static_vector<T, 4>();
        CHECK(!(lhs > rhs));
        CHECK(!(rhs > lhs));
        CHECK(lhs >= rhs);
        CHECK(rhs >= lhs);
    }

    // full
    {
        auto lhs = etl::static_vector<T, 4>(4);
        etl::iota(begin(lhs), end(lhs), T(1));
        auto rhs = etl::static_vector<T, 4>(4);
        etl::iota(begin(rhs), end(rhs), T(0));

        CHECK(lhs > rhs);
        CHECK(lhs >= rhs);

        CHECK(!(rhs > lhs));
        CHECK(!(rhs >= lhs));
    }

    // empty
    {
        auto data = etl::static_vector<T, 4>();
        CHECK(data.empty());
        CHECK(etl::erase(data, T(0)) == 0);
        CHECK(data.empty());
    }

    // range
    {
        auto data = etl::array{T(0), T(0), T(1), T(2), T(0), T(2)};
        auto vec  = etl::static_vector<T, 6>(begin(data), end(data));
        CHECK(vec.full());
        CHECK(etl::erase(vec, T(0)) == 3);
        CHECK(!(vec.full()));
        CHECK(vec.size() == 3);
    }

    return true;
}

constexpr auto test_all_cx() -> bool
{
    CHECK(test_cx<etl::int8_t>());
    CHECK(test_cx<etl::int16_t>());
    CHECK(test_cx<etl::int32_t>());
    CHECK(test_cx<etl::int64_t>());
    CHECK(test_cx<etl::uint8_t>());
    CHECK(test_cx<etl::uint16_t>());
    CHECK(test_cx<etl::uint32_t>());
    CHECK(test_cx<etl::uint64_t>());
    CHECK(test_cx<float>());
    CHECK(test_cx<double>());
    return true;
}

auto main() -> int
{
    CHECK(test_all_cx());
    static_assert(test_all_cx());
    return 0;
}
