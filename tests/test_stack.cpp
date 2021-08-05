// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

#include "etl/stack.hpp"

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
