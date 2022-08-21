/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/stack.hpp"

#include "etl/cstdint.hpp"
#include "etl/utility.hpp"
#include "etl/vector.hpp"

#include "testing/testing.hpp"

template <typename T>
auto test() -> bool
{
    using pair_type  = etl::pair<int, T>;
    using stack_type = etl::stack<pair_type, etl::static_vector<pair_type, 4>>;

    stack_type s {};
    assert(s.empty());

    s.push(etl::make_pair(1, T { 2 }));
    s.push(etl::make_pair(2, T { 6 }));
    s.push(etl::make_pair(3, T { 51 }));
    assert(s.size() == 3);
    assert(s.top().second == T { 51 });
    assert(s.size() == 3);

    s.pop();
    assert(etl::as_const(s).top().second == T { 6 });
    assert(s.size() == 2);

    s.emplace(42, T { 1 });
    assert(s.size() == 3);
    assert(s.top().first == 42);
    assert(s.top().second == T { 1 });

    auto sCopy = s;
    assert(sCopy == s);
    assert(s == sCopy);
    assert(!(sCopy != s));
    assert(!(s != sCopy));

    sCopy.pop();
    assert(sCopy != s);
    assert(s != sCopy);
    assert(!(sCopy == s));
    assert(!(s == sCopy));

    decltype(sCopy) sSwap {};
    sCopy.swap(sSwap);

    assert(sCopy.empty());
    assert(sSwap.size() == 2);
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
