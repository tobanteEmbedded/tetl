/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/algorithm.hpp"

#include "etl/array.hpp"
#include "etl/cstdint.hpp"
#include "etl/functional.hpp"
#include "etl/iterator.hpp"
#include "etl/numeric.hpp"
#include "etl/vector.hpp"

#include "testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    using vector_t = etl::static_vector<T, 4>;

    // copy to c array
    {
        auto s = etl::array<T, 4> { T { 1 }, T { 2 }, T { 3 }, T { 4 } };
        T d[4] = {};
        etl::copy(begin(s), end(s), etl::begin(d));
        assert(d[0] == T { 1 });
        assert(d[1] == T { 2 });
        assert(d[2] == T { 3 });
        assert(d[3] == T { 4 });
    }

    // copy to vector
    {
        auto s = etl::array<T, 4> { T { 1 }, T { 2 }, T { 3 }, T { 4 } };
        auto d = vector_t {};
        assert(d.size() == 0);
        etl::copy(begin(s), end(s), etl::back_inserter(d));
        assert(d.size() == 4);
        assert(d[0] == T { 1 });
        assert(d[1] == T { 2 });
        assert(d[2] == T { 3 });
        assert(d[3] == T { 4 });
    }

    auto s = etl::array<T, 4> {};
    s[0]   = T { 1 };
    s[1]   = T { 7 };
    s[2]   = T { 3 };
    s[3]   = T { 9 };

    auto p = [](auto val) { return static_cast<int>(val) >= 5; };

    // copy_if to c array
    {
        T d[4]    = {};
        auto* res = etl::copy_if(begin(s), end(s), etl::begin(d), p);
        assert(res == &d[2]);
        assert(d[0] == T { 7 });
        assert(d[1] == T { 9 });
        assert(d[2] == T { 0 });
        assert(d[3] == T { 0 });
    }

    // copy_if to vector
    {
        auto d = vector_t {};
        assert(d.size() == 0);
        etl::copy_if(begin(s), end(s), etl::back_inserter(d), p);
        assert(d.size() == 2);
        assert(d[0] == T { 7 });
        assert(d[1] == T { 9 });
    }

    // all elements
    {
        auto const source = etl::array { T(1), T(2), T(3), T(4) };
        T dest[4]         = {};
        etl::copy_n(begin(source), 4, etl::begin(dest));
        assert(dest[0] == T { 1 });
        assert(dest[1] == T { 2 });
        assert(dest[2] == T { 3 });
        assert(dest[3] == T { 4 });
    }

    // 2 elements
    {
        auto const source = etl::array { T(1), T(2), T(3), T(4) };
        T dest[3]         = {};
        etl::copy_n(begin(source), 2, etl::begin(dest));
        assert(dest[0] == T { 1 });
        assert(dest[1] == T { 2 });
        assert(dest[2] == T { 0 });
    }

    // copy_n to vector
    {
        auto const source = etl::array { T(1), T(2), T(3), T(4) };
        auto dest         = vector_t {};
        assert(dest.size() == 0);
        etl::copy_n(begin(source), source.size(), etl::back_inserter(dest));
        assert(dest.size() == 4);
        assert(dest[0] == T { 1 });
        assert(dest[1] == T { 2 });
        assert(dest[2] == T { 3 });
        assert(dest[3] == T { 4 });
    }

    // copy_backward to c array
    {
        auto const source = etl::array { T(1), T(2), T(3), T(4) };
        T dest[4]         = {};
        etl::copy_backward(begin(source), end(source), etl::end(dest));
        assert(dest[0] == T { 1 });
        assert(dest[1] == T { 2 });
        assert(dest[2] == T { 3 });
        assert(dest[3] == T { 4 });
    }
    return true;
}

constexpr auto test_all() -> bool
{
    assert(test<etl::uint8_t>());
    assert(test<etl::int8_t>());
    assert(test<etl::uint16_t>());
    assert(test<etl::int16_t>());
    assert(test<etl::uint32_t>());
    assert(test<etl::int32_t>());
    assert(test<etl::uint64_t>());
    assert(test<etl::int64_t>());
    assert(test<float>());
    assert(test<double>());

    return true;
}

auto main() -> int
{
    assert(test_all());

    // TODO: Fix
    // Fails on gcc-9, but passes clang-13 & gcc-11
    // static_assert(test_all());

    return 0;
}