// SPDX-License-Identifier: BSL-1.0

#include <etl/stack.hpp>

#include <etl/cstdint.hpp>
#include <etl/utility.hpp>
#include <etl/vector.hpp>

#include "testing/testing.hpp"

template <typename T>
auto test() -> bool
{
    using pair_type  = etl::pair<int, T>;
    using stack_type = etl::stack<pair_type, etl::static_vector<pair_type, 4>>;

    stack_type s{};
    CHECK(s.empty());

    s.push(etl::make_pair(1, T{2}));
    s.push(etl::make_pair(2, T{6}));
    s.push(etl::make_pair(3, T{51}));
    CHECK(s.size() == 3);
    CHECK(s.top().second == T{51});
    CHECK(s.size() == 3);

    s.pop();
    CHECK(etl::as_const(s).top().second == T{6});
    CHECK(s.size() == 2);

    s.emplace(42, T{1});
    CHECK(s.size() == 3);
    CHECK(s.top().first == 42);
    CHECK(s.top().second == T{1});

    auto sCopy = s;
    CHECK(sCopy == s);
    CHECK(s == sCopy);
    CHECK(!(sCopy != s));
    CHECK(!(s != sCopy));

    sCopy.pop();
    CHECK(sCopy != s);
    CHECK(s != sCopy);
    CHECK(!(sCopy == s));
    CHECK(!(s == sCopy));

    decltype(sCopy) sSwap{};
    sCopy.swap(sSwap);

    CHECK(sCopy.empty());
    CHECK(sSwap.size() == 2);
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
