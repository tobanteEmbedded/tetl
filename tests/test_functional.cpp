/*
Copyright (c) 2019-2020, Tobias Hienzsch
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
*/

#include "etl/functional.hpp"

#include "catch2/catch.hpp"

TEMPLATE_TEST_CASE("functional: plus", "[functional]", int, float, double)
{
    REQUIRE(etl::plus<TestType> {}(TestType {2}, TestType {1}) == TestType {3});
    REQUIRE(etl::plus<TestType> {}(TestType {1}, TestType {1}) == TestType {2});
    REQUIRE(etl::plus<TestType> {}(TestType {100}, TestType {100}) == TestType {200});

    REQUIRE(etl::plus<> {}(TestType {2}, TestType {1}) == TestType {3});
    REQUIRE(etl::plus<> {}(TestType {1}, TestType {1}) == TestType {2});
    REQUIRE(etl::plus<> {}(TestType {100}, TestType {100}) == TestType {200});
}

TEMPLATE_TEST_CASE("functional: minus", "[functional]", int, float, double)
{
    REQUIRE(etl::minus<TestType> {}(TestType {99}, 98) == TestType {1});
    REQUIRE(etl::minus<> {}(TestType {2}, TestType {1}) == TestType {1});
    REQUIRE(etl::minus<> {}(TestType {1}, TestType {1}) == TestType {0});
    REQUIRE(etl::minus<> {}(TestType {99}, TestType {100}) == TestType {-1});

    REQUIRE(etl::minus<TestType> {}(TestType {99}, TestType {98}) == TestType {1});
}

TEMPLATE_TEST_CASE("functional: multiplies", "[functional]", int, float, double)
{
    REQUIRE(etl::multiplies<TestType> {}(TestType {99}, 2) == TestType {198});
    REQUIRE(etl::multiplies<> {}(TestType {2}, TestType {1}) == TestType {2});
    REQUIRE(etl::multiplies<> {}(TestType {1}, TestType {1}) == TestType {1});
    REQUIRE(etl::multiplies<> {}(TestType {99}, TestType {100}) == TestType {9900});

    REQUIRE(etl::multiplies<TestType> {}(TestType {99}, TestType {1}) == TestType {99});
}

TEMPLATE_TEST_CASE("functional: divides", "[functional]", int, float, double)
{
    REQUIRE(etl::divides<TestType> {}(TestType {100}, 2) == TestType {50});
    REQUIRE(etl::divides<> {}(TestType {2}, TestType {1}) == TestType {2});
    REQUIRE(etl::divides<> {}(TestType {1}, TestType {1}) == TestType {1});
    REQUIRE(etl::divides<> {}(TestType {100}, TestType {100}) == TestType {1});

    REQUIRE(etl::divides<TestType> {}(TestType {99}, TestType {1}) == TestType {99});
}

TEMPLATE_TEST_CASE("functional: modulus", "[functional]", int, unsigned)
{
    REQUIRE(etl::modulus<TestType> {}(TestType {100}, 2) == TestType {0});
    REQUIRE(etl::modulus<> {}(TestType {2}, TestType {1}) == TestType {0});
    REQUIRE(etl::modulus<> {}(TestType {5}, TestType {3}) == TestType {2});
    REQUIRE(etl::modulus<> {}(TestType {100}, TestType {99}) == TestType {1});

    REQUIRE(etl::modulus<TestType> {}(TestType {99}, TestType {90}) == TestType {9});
}

TEMPLATE_TEST_CASE("functional: negate", "[functional]", int, float, double)
{
    REQUIRE(etl::negate<TestType> {}(TestType {50}) == TestType {-50});
    REQUIRE(etl::negate<> {}(TestType {2}) == TestType {-2});
    REQUIRE(etl::negate<> {}(TestType {-1}) == TestType {1});
    REQUIRE(etl::negate<> {}(TestType {100}) == TestType {-100});

    REQUIRE(etl::negate<TestType> {}(TestType {99}) == TestType {-99});
}

TEMPLATE_TEST_CASE("functional: equal_to", "[functional]", int, float, double)
{
    REQUIRE(etl::equal_to<TestType> {}(TestType {99}, 99));
    REQUIRE(etl::equal_to<> {}(TestType {1}, TestType {1}));

    REQUIRE_FALSE(etl::equal_to<> {}(TestType {2}, TestType {1}));
    REQUIRE_FALSE(etl::equal_to<> {}(TestType {99}, TestType {100}));
    REQUIRE_FALSE(etl::equal_to<TestType> {}(TestType {99}, TestType {98}));
}

TEMPLATE_TEST_CASE("functional: function - ctor", "[functional]", int, float, double)
{
    using function_t = etl::function<16, TestType(void)>;
    auto func        = function_t {[]() { return TestType {1}; }};
    REQUIRE(func() == TestType {1});
    REQUIRE(func() == TestType {1});
}

TEMPLATE_TEST_CASE("functional: function - ctor copy", "[functional]", int, float, double)
{
    using function_t = etl::function<16, TestType(void)>;
    auto func        = function_t {[]() { return TestType {1}; }};
    auto func2       = func;
    func             = func2;
    REQUIRE(func() == TestType {1});
    REQUIRE(func() == TestType {1});
}

TEMPLATE_TEST_CASE("functional: function - assigment copy", "[functional]", int, float,
                   double)
{
    using function_t  = etl::function<16, TestType(void)>;
    auto func         = function_t {[]() { return TestType {1}; }};
    auto const& func2 = func;
    REQUIRE(func() == TestType {1});
    REQUIRE(func2() == TestType {1});
    REQUIRE(func2() == TestType {1});
}

TEMPLATE_TEST_CASE("functional: function_view - ctor", "[functional]", int, float, double)
{
    using function_t = etl::function<16, TestType(TestType)>;
    auto func        = function_t {[](TestType val) { return TestType {val}; }};
    auto handler     = [](etl::function_view<TestType(TestType)> f) {
        REQUIRE(f(1) == TestType {1});
        REQUIRE(f(2) == TestType {2});
    };

    handler(func);
}