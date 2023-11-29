// SPDX-License-Identifier: BSL-1.0

#include "etl/vector.hpp"

#include "etl/algorithm.hpp"
#include "etl/cstdint.hpp"
#include "etl/numeric.hpp"
#include "etl/type_traits.hpp"
#include "etl/utility.hpp"

#include "testing/testing.hpp"

using etl::all_of;
using etl::static_vector;

template <typename T>
constexpr auto test_cx() -> bool
{
    {
        using vec_t = static_vector<T, 16>;

        using etl::is_same_v;
        assert((is_same_v<T, typename vec_t::value_type>));
        assert((is_same_v<T&, typename vec_t::reference>));
        assert((is_same_v<T const&, typename vec_t::const_reference>));
        assert((is_same_v<T*, typename vec_t::pointer>));
        assert((is_same_v<T const*, typename vec_t::const_pointer>));
        assert((is_same_v<T*, typename vec_t::iterator>));
        assert((is_same_v<T const*, typename vec_t::const_iterator>));
    }

    {
        using vec_t = static_vector<T, 16>;

        assert(etl::is_trivial_v<T>);
        assert(etl::is_default_constructible_v<vec_t>);
        assert(etl::is_trivially_destructible_v<vec_t>);

        struct NonTrivial {
            ~NonTrivial() { } // NOLINT
        };

        using non_trivial_vec_t = static_vector<NonTrivial, 16>;

        assert(!(etl::is_trivial_v<NonTrivial>));
        assert(!(etl::is_trivially_destructible_v<non_trivial_vec_t>));
    }

    {
        auto zero = static_vector<T, 0> {};
        assert(zero.capacity() == zero.max_size());
        assert(zero.empty());
        assert(zero.size() == 0);
        assert(zero.capacity() == 0);
        assert(zero.data() == nullptr);
        assert(zero.full());
    }

    {
        static_vector<T, 16> lhs {};
        assert(lhs.empty());
        assert(lhs.size() == 0);
        assert(!(lhs.full()));

        assert(etl::begin(lhs) == etl::end(lhs));
        assert(etl::cbegin(lhs) == etl::cend(lhs));
        assert(etl::begin(etl::as_const(lhs)) == etl::end(etl::as_const(lhs)));

        static_vector<T, 16> rhs {};
        assert(rhs.empty());
        assert(rhs.size() == 0);
        assert(!(rhs.full()));

        // comparison empty
        assert(lhs == rhs);
        assert(rhs == lhs);
        assert(!(lhs != rhs));
        assert(!(rhs != lhs));
    }

    {
        auto first  = static_vector<T, 4>(4);
        auto second = static_vector<T, 4> { begin(first), end(first) };
        assert(first == second);
    }

    {
        static_vector<T, 16> vec(8);
        assert(vec.size() == 8);
        assert(all_of(begin(vec), end(vec), [](T v) { return v == T(); }));
    }

    {
        static_vector<T, 16> vec(16, T(42));
        assert(vec.size() == 16);
        assert(all_of(begin(vec), end(vec), [](T v) { return v == T(42); }));
    }

    {
        auto first = static_vector<T, 4>(4);
        static_vector<T, 4> const& second { first };
        assert(first == second);
    }

    {
        auto first = static_vector<T, 4>(4);
        static_vector<T, 4> copy { etl::move(first) };

        auto cmp = [](auto val) { return val == T(0); };
        assert(all_of(begin(copy), end(copy), cmp));
    }

    {
        auto first = static_vector<T, 4>(4);
        static_vector<T, 4> copy {};
        copy = first;
        assert(first == copy);
    }

    {
        auto first = static_vector<T, 4>(4);
        static_vector<T, 4> copy {};
        copy = etl::move(first);

        auto cmp = [](auto val) { return val == T(0); };
        assert(all_of(begin(copy), end(copy), cmp));
    }

    {
        etl::static_vector<T, 16> vec {};
        assert(vec.empty());
        assert(etl::begin(vec) == etl::end(vec));
        assert(etl::cbegin(vec) == etl::cend(vec));
        assert(etl::begin(etl::as_const(vec)) == etl::end(etl::as_const(vec)));

        vec.push_back(T { 2 });
        assert(!(etl::begin(vec) == etl::end(vec)));
        assert(!(etl::cbegin(vec) == etl::cend(vec)));
        assert(!(begin(as_const(vec)) == end(as_const(vec))));
    }

    {
        using etl::all_of;

        auto vec = etl::static_vector<T, 4> {};
        assert(vec.size() == 0);

        // grow
        vec.resize(etl::size_t { 2 });
        assert(vec.size() == 2);
        assert(all_of(begin(vec), end(vec), [](auto x) { return x == T(); }));

        // grow full capacity
        vec.resize(etl::size_t { 4 });
        assert(vec.size() == 4);
        assert(all_of(begin(vec), end(vec), [](auto x) { return x == T(); }));

        // same size
        vec.resize(etl::size_t { 4 });
        assert(vec.size() == 4);
        assert(all_of(begin(vec), end(vec), [](auto x) { return x == T(); }));

        // shrink
        vec.resize(etl::size_t { 2 });
        assert(vec.size() == 2);
    }

    {
        using etl::all_of;
        using etl::as_const;

        auto a = etl::static_vector<T, 4> {};
        a.assign(4, T { 42 });
        assert(a.size() == 4);
        assert(a.front() == 42);
        assert(a.back() == 42);
        assert(as_const(a).size() == 4);
        assert(as_const(a).front() == 42);
        assert(as_const(a).back() == 42);
        assert(all_of(begin(a), end(a), [](auto val) { return val == T(42); }));

        auto b = etl::static_vector<T, 4> { 4 };
        b.assign(a.begin(), a.end());
        assert(b.size() == 4);
        assert(b.front() == 42);
        assert(b.back() == 42);
        assert(all_of(begin(b), end(b), [](auto val) { return val == T(42); }));
    }

    {
        auto vec = etl::static_vector<T, 4> {};
        assert(vec.size() == 0);
        vec.push_back(T(1));
        assert(vec.size() == 1);
        vec.pop_back();
        assert(vec.size() == 0);
    }

    {
        etl::static_vector<T, 16> vec { {} };
        assert(vec.empty());

        vec.push_back(T { 1 });
        assert(!(vec.empty()));
        assert(vec.front() == T { 1 });
        assert(vec.back() == T { 1 });

        vec.push_back(T { 2 });
        assert(!(vec.empty()));
        assert(vec.front() == T { 1 });
        assert(vec.back() == T { 2 });

        assert(!(etl::begin(vec) == etl::end(vec)));
        assert(!(etl::cbegin(vec) == etl::cend(vec)));
        assert(!(begin(as_const(vec)) == end(as_const(vec))));
    }

    {
        auto vec = etl::static_vector<T, 4> { 4 };
        etl::generate(etl::begin(vec), etl::end(vec), [v = T {}]() mutable { return v += T(1); });

        assert(vec.front() == T(1));
        vec.erase(vec.begin());
        assert(vec.front() == T(2));
    }

    // method
    {
        auto lhs       = etl::static_vector<T, 4> { 4 };
        auto generator = [v = T {}]() mutable { return v += T(1); };

        etl::generate(etl::begin(lhs), etl::end(lhs), generator);
        auto rhs = lhs;

        lhs.swap(rhs);
        assert(lhs == rhs);
        rhs.swap(lhs);
        assert(lhs == rhs);
    }

    // free function
    {
        auto lhs = etl::static_vector<T, 4> { { T(1), T(2), T(3), T(4) } };
        auto rhs = lhs;
        assert(lhs.size() == 4);
        assert(rhs.size() == 4);

        using ::etl::swap;
        swap(lhs, rhs);
        assert(lhs == rhs);
        swap(rhs, lhs);
        assert(lhs == rhs);
    }

    //  empty
    {
        auto lhs1       = etl::static_vector<T, 4> {};
        auto const rhs1 = etl::static_vector<T, 4> {};
        assert(lhs1 == rhs1);
        assert(!(lhs1 != rhs1));

        auto const lhs2 = etl::static_vector<T, 4>();
        auto const rhs2 = etl::static_vector<T, 4>(2);
        assert(lhs2 != rhs2);
        assert(!(lhs2 == rhs2));

        auto const lhs3 = etl::static_vector<T, 4>(2);
        auto const rhs3 = etl::static_vector<T, 4>();
        assert(lhs3 != rhs3);
        assert(!(lhs3 == rhs3));
    }

    // with elements
    {
        auto lhs1 = etl::static_vector<T, 4> {};
        lhs1.push_back(T(1));
        lhs1.push_back(T(2));
        auto rhs1 = etl::static_vector<T, 4> {};
        rhs1.push_back(T(1));
        rhs1.push_back(T(2));

        assert(lhs1 == rhs1);
        assert(!(lhs1 != rhs1));

        auto lhs2 = etl::static_vector<T, 4> {};
        lhs2.push_back(T(1));
        lhs2.push_back(T(2));
        auto rhs2 = etl::static_vector<T, 4> {};
        rhs2.push_back(T(1));
        rhs2.push_back(T(3));

        assert(lhs2 != rhs2);
        assert(!(lhs2 == rhs2));
    }

    {
        auto lhs       = etl::static_vector<T, 4>();
        auto const rhs = etl::static_vector<T, 4>();
        assert(!(lhs < rhs));
        assert(!(rhs < lhs));
        assert(lhs <= rhs);
        assert(rhs <= lhs);
    }

    // full
    {
        auto lhs = etl::static_vector<T, 4>(4);
        etl::iota(begin(lhs), end(lhs), T(0));
        auto rhs = etl::static_vector<T, 4>(4);
        etl::iota(begin(rhs), end(rhs), T(1));

        assert(lhs < rhs);
        assert(lhs <= rhs);

        assert(!(rhs < lhs));
        assert(!(rhs <= lhs));
    }

    {
        auto lhs       = etl::static_vector<T, 4>();
        auto const rhs = etl::static_vector<T, 4>();
        assert(!(lhs > rhs));
        assert(!(rhs > lhs));
        assert(lhs >= rhs);
        assert(rhs >= lhs);
    }

    // full
    {
        auto lhs = etl::static_vector<T, 4>(4);
        etl::iota(begin(lhs), end(lhs), T(1));
        auto rhs = etl::static_vector<T, 4>(4);
        etl::iota(begin(rhs), end(rhs), T(0));

        assert(lhs > rhs);
        assert(lhs >= rhs);

        assert(!(rhs > lhs));
        assert(!(rhs >= lhs));
    }

    // empty
    {
        auto data = etl::static_vector<T, 4>();
        assert(data.empty());
        assert(etl::erase(data, T(0)) == 0);
        assert(data.empty());
    }

    // range
    {
        auto data = etl::array { T(0), T(0), T(1), T(2), T(0), T(2) };
        auto vec  = etl::static_vector<T, 6>(begin(data), end(data));
        assert(vec.full());
        assert(etl::erase(vec, T(0)) == 3);
        assert(!(vec.full()));
        assert(vec.size() == 3);
    }

    return true;
}

constexpr auto test_all_cx() -> bool
{
    assert(test_cx<etl::int8_t>());
    assert(test_cx<etl::int16_t>());
    assert(test_cx<etl::int32_t>());
    assert(test_cx<etl::int64_t>());
    assert(test_cx<etl::uint8_t>());
    assert(test_cx<etl::uint16_t>());
    assert(test_cx<etl::uint32_t>());
    assert(test_cx<etl::uint64_t>());
    assert(test_cx<float>());
    assert(test_cx<double>());
    return true;
}

auto main() -> int
{
    assert(test_all_cx());
    static_assert(test_all_cx());
    return 0;
}