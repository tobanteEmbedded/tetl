// SPDX-License-Identifier: BSL-1.0

#include <etl/span.hpp>

#include <etl/algorithm.hpp>
#include <etl/cstdint.hpp>
#include <etl/iterator.hpp>
#include <etl/utility.hpp>
#include <etl/vector.hpp>

#include "testing/testing.hpp"

template <typename T>
auto test() -> bool
{
    // deduction guides
    // from C array
    {
        T arr[16] = {};
        auto sp   = etl::span{arr};
        assert(sp.data() == &arr[0]);
        assert(sp.size() == 16);
    }

    // from etl::array
    {
        auto arr = etl::array<T, 8>{};
        auto sp  = etl::span{arr};
        assert(sp.data() == arr.data());
        assert(sp.size() == 8);
    }

    // from etl::array const
    {
        auto const arr = etl::array<T, 8>{};
        auto const sp  = etl::span{arr};
        assert(sp.data() == arr.data());
        assert(sp.size() == 8);
    }

    // from Container
    {
        auto vec = etl::static_vector<T, 8>{};
        vec.push_back(T{});
        vec.push_back(T{});
        auto sp = etl::span{vec};
        assert(sp.data() == vec.data());
        assert(sp.size() == 2);
    }

    // from Container const
    {
        auto const vec = []() {
            auto v = etl::static_vector<T, 8>{};
            v.push_back(T{});
            v.push_back(T{});
            return v;
        }();

        auto const sp = etl::span{vec};
        assert(sp.data() == vec.data());
        assert(sp.size() == 2);
    }

    {
        auto sp = etl::span<char>{};
        assert(sp.data() == nullptr);
        assert(sp.size() == 0);
        assert(sp.empty());
    }

    // static extent
    {
        auto arr = etl::array<T, 8>{};
        auto sp  = etl::span<T, 8>{etl::begin(arr), etl::size(arr)};
        assert(!sp.empty());
        assert(sp.data() == arr.data());
        assert(sp.size() == arr.size());
        assert(sp.extent == arr.size());
    }

    // static array
    {
        auto arr = etl::array<T, 8>{};
        auto sp  = etl::span<T>{etl::begin(arr), etl::size(arr)};
        assert(!sp.empty());
        assert(sp.data() == arr.data());
        assert(sp.size() == arr.size());
        assert(sp.extent == etl::dynamic_extent);
    }

    // static vector
    {
        auto vec = etl::static_vector<T, 8>{};
        auto rng = []() { return T{42}; };
        etl::generate_n(etl::back_inserter(vec), 4, rng);

        auto sp = etl::span<T>{etl::begin(vec), etl::size(vec)};
        assert(!sp.empty());
        assert(sp.data() == vec.data());
        assert(sp.size() == vec.size());
        assert(sp.extent == etl::dynamic_extent);
        assert(etl::all_of(etl::begin(sp), etl::end(sp), [](auto& x) { return x == T{42}; }));
    }

    // empty
    {
        auto sp = etl::span<T>{};
        assert(sp.begin() == sp.end());
        assert(etl::begin(sp) == etl::end(sp));
        assert(sp.size() == 0);
    }

    // ranged-for
    {
        auto data = etl::array<T, 4>{};
        auto sp   = etl::span<T>{etl::begin(data), etl::size(data)};
        assert(!(sp.begin() == sp.end()));
        assert(!(etl::begin(sp) == etl::end(sp)));

        auto counter = 0;
        for (auto const& x : sp) {
            etl::ignore_unused(x);
            counter++;
        }
        assert(counter == 4);
    }

    // algorithm
    {
        auto data = etl::array<T, 4>{};
        auto sp   = etl::span<T>{etl::begin(data), etl::size(data)};
        assert(!(sp.begin() == sp.end()));
        assert(!(etl::begin(sp) == etl::end(sp)));

        auto counter = 0;
        etl::for_each(etl::begin(sp), etl::end(sp), [&counter](auto /*unused*/) { counter++; });
        assert(counter == 4);
    }

    {
        auto rng = []() {
            static auto i = T{127};
            return T{i--};
        };

        auto vec = etl::static_vector<T, 8>{};
        etl::generate_n(etl::back_inserter(vec), 4, rng);
        auto sp = etl::span<T>{etl::begin(vec), etl::size(vec)};
        assert(sp[0] == T{127});
        assert(sp[1] == T{126});
        assert(sp[2] == T{125});
        assert(sp[3] == T{124});

        auto const csp = etl::span{sp};
        assert(csp[0] == T{127});
        assert(csp[1] == T{126});
        assert(csp[2] == T{125});
        assert(csp[3] == T{124});
    }

    {
        auto vec = etl::static_vector<T, 6>{};
        etl::generate_n(etl::back_inserter(vec), 4, []() { return T{42}; });
        auto sp = etl::span<T>{etl::begin(vec), etl::size(vec)};

        assert(sp.size_bytes() == 4 * sizeof(T));
    }

    {
        auto data = etl::array{T(0), T(1), T(2), T(3), T(4), T(5), T(6)};
        auto sp   = etl::span<T>{data};

        auto one = sp.first(1);
        assert(one.size() == 1);
        assert(one[0] == T(0));

        auto two = sp.first(2);
        assert(two.size() == 2);
        assert(two[0] == T(0));
        assert(two[1] == T(1));

        auto onet = sp.template first<1>();
        assert(onet.size() == 1);
        assert(onet[0] == T(0));

        auto twot = sp.template first<2>();
        assert(twot.size() == 2);
        assert(twot[0] == T(0));
        assert(twot[1] == T(1));
    }

    {
        auto data = etl::array{T(0), T(1), T(2), T(3), T(4), T(5), T(6)};
        auto sp   = etl::span<T>{data};

        auto one = sp.last(1);
        assert(one.size() == 1);
        assert(one[0] == T(6));

        auto two = sp.last(2);
        assert(two.size() == 2);
        assert(two[0] == T(5));
        assert(two[1] == T(6));

        auto onet = sp.template last<1>();
        assert(onet.size() == 1);
        assert(onet[0] == T(6));

        auto twot = sp.template last<2>();
        assert(twot.size() == 2);
        assert(twot[0] == T(5));
        assert(twot[1] == T(6));
    }

    {
        auto data = etl::array<T, 6>{};
        auto sp   = etl::span<T>{data};
        assert(etl::as_bytes(sp).size() == sizeof(T) * data.size());
        assert(etl::as_writable_bytes(sp).size() == sizeof(T) * data.size());
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
