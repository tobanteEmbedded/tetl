/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/stack.hpp"

#include "etl/cstdint.hpp"
#include "etl/utility.hpp"
#include "etl/vector.hpp"

#include "catch2/catch_template_test_macros.hpp"

TEMPLATE_TEST_CASE("stack: stack<static_vector>", "[stack]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    using pair_type  = etl::pair<int, TestType>;
    using stack_type = etl::stack<pair_type, etl::static_vector<pair_type, 4>>;

    stack_type s {};
    REQUIRE(s.empty());

    s.push(etl::make_pair(1, TestType { 2 }));
    s.push(etl::make_pair(2, TestType { 6 }));
    s.push(etl::make_pair(3, TestType { 51 }));
    REQUIRE(s.size() == 3);
    REQUIRE(s.top().second == TestType { 51 });
    REQUIRE(s.size() == 3);

    s.pop();
    REQUIRE(etl::as_const(s).top().second == TestType { 6 });
    REQUIRE(s.size() == 2);

    s.emplace(42, TestType { 1 });
    REQUIRE(s.size() == 3);
    REQUIRE(s.top().first == 42);
    REQUIRE(s.top().second == TestType { 1 });

    auto sCopy = s;
    REQUIRE(sCopy == s);
    REQUIRE(s == sCopy);
    REQUIRE_FALSE(sCopy != s);
    REQUIRE_FALSE(s != sCopy);

    sCopy.pop();
    REQUIRE(sCopy != s);
    REQUIRE(s != sCopy);
    REQUIRE_FALSE(sCopy == s);
    REQUIRE_FALSE(s == sCopy);

    decltype(sCopy) sSwap {};
    sCopy.swap(sSwap);

    REQUIRE(sCopy.empty());
    REQUIRE(sSwap.size() == 2);
}
