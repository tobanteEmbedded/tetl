// SPDX-License-Identifier: BSL-1.0

#include "etl/algorithm.hpp"

#include "etl/array.hpp"
#include "etl/cstdint.hpp"
#include "etl/functional.hpp"
#include "etl/iterator.hpp"
#include "etl/string.hpp"
#include "etl/vector.hpp"

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    using etl::transform;

    etl::array<T, 4> a {T(2), T(2), T(2), T(2)};
    auto func = [](auto v) { return static_cast<T>(v * 2); };
    transform(begin(a), end(a), begin(a), func);
    assert((etl::all_of(begin(a), end(a), [](auto v) { return v == 4; })));

    etl::static_string<32> str("hello");
    etl::static_vector<T, 8> vec {};
    auto const identity = [](auto c) -> T { return static_cast<T>(c); };
    transform(begin(str), end(str), etl::back_inserter(vec), identity);

    assert((vec[0] == static_cast<T>('h')));
    assert((vec[1] == static_cast<T>('e')));
    assert((vec[2] == static_cast<T>('l')));
    assert((vec[3] == static_cast<T>('l')));
    assert((vec[4] == static_cast<T>('o')));

    transform(cbegin(vec), cend(vec), cbegin(vec), begin(vec), etl::plus<T> {});

    assert((vec[0] == static_cast<T>('h' * 2)));
    assert((vec[1] == static_cast<T>('e' * 2)));
    assert((vec[2] == static_cast<T>('l' * 2)));
    assert((vec[3] == static_cast<T>('l' * 2)));
    assert((vec[4] == static_cast<T>('o' * 2)));

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
    static_assert(test_all());
    return 0;
}
