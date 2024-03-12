// SPDX-License-Identifier: BSL-1.0

#include <etl/algorithm.hpp>

#include <etl/array.hpp>
#include <etl/cstdint.hpp>
#include <etl/functional.hpp>
#include <etl/iterator.hpp>
#include <etl/numeric.hpp>
#include <etl/vector.hpp>

#include "testing/iterator_types.hpp"
#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    using vector_t = etl::static_vector<T, 4>;

    // copy to c array
    {
        auto s = etl::array<T, 4>{T{1}, T{2}, T{3}, T{4}};
        T d[4] = {};
        etl::copy(begin(s), end(s), etl::begin(d));
        ASSERT(d[0] == T{1});
        ASSERT(d[1] == T{2});
        ASSERT(d[2] == T{3});
        ASSERT(d[3] == T{4});
    }

    // copy to vector
    {
        auto s = etl::array<T, 4>{T{1}, T{2}, T{3}, T{4}};
        auto d = vector_t{};
        ASSERT(d.size() == 0);
        etl::copy(begin(s), end(s), etl::back_inserter(d));
        ASSERT(d.size() == 4);
        ASSERT(d[0] == T{1});
        ASSERT(d[1] == T{2});
        ASSERT(d[2] == T{3});
        ASSERT(d[3] == T{4});
    }

    auto const s = etl::array{T(1), T(7), T(3), T(9)};

    auto p = [](auto val) { return static_cast<int>(val) >= 5; };

    // copy_if to c array
    {
        T d[4]    = {};
        auto* res = etl::copy_if(begin(s), end(s), etl::begin(d), p);
        ASSERT(res == &d[2]);
        ASSERT(d[0] == T{7});
        ASSERT(d[1] == T{9});
        ASSERT(d[2] == T{0});
        ASSERT(d[3] == T{0});
    }

    // copy_if to vector
    {
        auto d = vector_t{};
        ASSERT(d.size() == 0);
        etl::copy_if(begin(s), end(s), etl::back_inserter(d), p);
        ASSERT(d.size() == 2);
        ASSERT(d[0] == T{7});
        ASSERT(d[1] == T{9});
    }

    // all elements
    {
        auto const source = etl::array{T(1), T(2), T(3), T(4)};
        T dest[4]         = {};
        etl::copy_n(begin(source), 4, etl::begin(dest));
        ASSERT(dest[0] == T{1});
        ASSERT(dest[1] == T{2});
        ASSERT(dest[2] == T{3});
        ASSERT(dest[3] == T{4});
    }

    // 2 elements
    {
        auto const source = etl::array{T(1), T(2), T(3), T(4)};
        T dest[3]         = {};
        etl::copy_n(begin(source), 2, etl::begin(dest));
        ASSERT(dest[0] == T{1});
        ASSERT(dest[1] == T{2});
        ASSERT(dest[2] == T{0});
    }

    // copy_n to vector
    {
        auto const source = etl::array{T(1), T(2), T(3), T(4)};
        auto dest         = vector_t{};
        ASSERT(dest.size() == 0);
        etl::copy_n(begin(source), source.size(), etl::back_inserter(dest));
        ASSERT(dest.size() == 4);
        ASSERT(dest[0] == T{1});
        ASSERT(dest[1] == T{2});
        ASSERT(dest[2] == T{3});
        ASSERT(dest[3] == T{4});
    }

    // copy_backward to c array
    {
        auto const source = etl::array{T(1), T(2), T(3), T(4)};
        T dest[4]         = {};
        etl::copy_backward(begin(source), end(source), etl::end(dest));
        ASSERT(dest[0] == T{1});
        ASSERT(dest[1] == T{2});
        ASSERT(dest[2] == T{3});
        ASSERT(dest[3] == T{4});
    }

    // input iterator
    {
        auto d = etl::static_vector<T, 4>{};
        etl::copy(InIter(begin(s)), InIter(end(s)), etl::back_inserter(d));
        ASSERT(etl::equal(begin(s), end(s), begin(d), end(d)));
    }
    // forward iterator
    {
        auto d = etl::static_vector<T, 4>{};
        etl::copy(FwdIter(begin(s)), FwdIter(end(s)), etl::back_inserter(d));
        ASSERT(etl::equal(begin(s), end(s), begin(d), end(d)));
    }
    return true;
}

constexpr auto test_all() -> bool
{
    ASSERT(test<etl::uint8_t>());
    ASSERT(test<etl::int8_t>());
    ASSERT(test<etl::uint16_t>());
    ASSERT(test<etl::int16_t>());
    ASSERT(test<etl::uint32_t>());
    ASSERT(test<etl::int32_t>());
    ASSERT(test<etl::uint64_t>());
    ASSERT(test<etl::int64_t>());
    ASSERT(test<float>());
    ASSERT(test<double>());

    return true;
}

auto main() -> int
{
    ASSERT(test_all());
    static_assert(test_all());

    return 0;
}
