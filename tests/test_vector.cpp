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

#include "etl/algorithm.hpp"
#include "etl/vector.hpp"

#include "catch2/catch.hpp"

TEMPLATE_TEST_CASE("stack_vector: construct default", "[stack_vector]", char,
                   int, float)
{
    using vector_t = etl::stack_vector<TestType, 16>;
    auto vec       = vector_t {};
    REQUIRE(vec.empty());
    REQUIRE(vec.size() == 0);
    REQUIRE(vec.capacity() == vec.max_size());
    REQUIRE(std::is_same_v<TestType, typename vector_t::value_type>);
    REQUIRE(std::is_same_v<TestType&, typename vector_t::reference>);
    REQUIRE(
        std::is_same_v<TestType const&, typename vector_t::const_reference>);
    REQUIRE(std::is_same_v<TestType*, typename vector_t::pointer>);
    REQUIRE(std::is_same_v<TestType const*, typename vector_t::const_pointer>);
    REQUIRE(std::is_same_v<TestType*, typename vector_t::iterator>);
    REQUIRE(std::is_same_v<TestType const*, typename vector_t::const_iterator>);
}

TEMPLATE_TEST_CASE("stack_vector: construct(count)", "[stack_vector]", int,
                   float)
{
    using vector_t = etl::stack_vector<TestType, 2>;

    auto vec1 = vector_t {1};
    REQUIRE_FALSE(vec1.empty());
    REQUIRE(vec1.size() == 1);

    auto vec2 = vector_t {2};
    REQUIRE_FALSE(vec2.empty());
    REQUIRE(vec2.size() == 2);
}

TEMPLATE_TEST_CASE("stack_vector: construct(count, value)", "[stack_vector]",
                   int, float)
{
    using vector_t = etl::stack_vector<TestType, 2>;
    auto vec       = vector_t {2, TestType(143)};
    REQUIRE_FALSE(vec.empty());
    REQUIRE(vec.size() == 2);
    REQUIRE(vec.front() == TestType(143));
    REQUIRE(vec.back() == TestType(143));
}

TEMPLATE_TEST_CASE("stack_vector: construct(copy)", "[stack_vector]", int,
                   float)
{
    using vector_t = etl::stack_vector<TestType, 2>;
    auto vec       = vector_t {2, TestType(143)};

    REQUIRE_FALSE(vec.empty());
    REQUIRE(vec.size() == 2);

    auto const vec2 = vec;
    REQUIRE(vec.size() == 2);

    REQUIRE(vec2.size() == 2);
    REQUIRE(vec2.front() == TestType(143));
    REQUIRE(vec2.back() == TestType(143));
}

TEMPLATE_TEST_CASE("stack_vector: construct(move)", "[stack_vector]", int,
                   float)
{
    using vector_t = etl::stack_vector<TestType, 2>;
    auto vec       = vector_t {2, TestType(143)};

    REQUIRE_FALSE(vec.empty());
    REQUIRE(vec.size() == 2);

    auto const vec2 = vector_t {std::move(vec)};
    REQUIRE(vec.size() == 0);

    REQUIRE(vec2.size() == 2);
    REQUIRE(vec2.front() == TestType(143));
    REQUIRE(vec2.back() == TestType(143));
}

TEMPLATE_TEST_CASE("stack_vector: operator=(copy)", "[stack_vector]", int,
                   float)
{
    using vector_t = etl::stack_vector<TestType, 2>;
    auto vec       = vector_t {2, TestType(143)};

    REQUIRE_FALSE(vec.empty());
    REQUIRE(vec.size() == 2);

    auto vec2 = vector_t {};
    vec2      = vec;
    REQUIRE(vec.size() == 2);

    REQUIRE(vec2.size() == 2);
    REQUIRE(vec2.front() == TestType(143));
    REQUIRE(vec2.back() == TestType(143));
}

TEMPLATE_TEST_CASE("stack_vector: operator=(move)", "[stack_vector]", int,
                   float)
{
    using vector_t = etl::stack_vector<TestType, 2>;
    auto vec       = vector_t {2, TestType(143)};

    REQUIRE_FALSE(vec.empty());
    REQUIRE(vec.size() == 2);

    auto vec2 = vector_t {};
    vec2      = std::move(vec);
    REQUIRE(vec.size() == 0);

    REQUIRE(vec2.size() == 2);
    REQUIRE(vec2.front() == TestType(143));
    REQUIRE(vec2.back() == TestType(143));
}

TEST_CASE("stack_vector: destruct", "[stack_vector]")
{
    auto currentCount = 0;
    struct Counter
    {
        Counter(int* c) : counter_ {c} { }
        ~Counter() noexcept { (*counter_)++; }
        int* counter_;
    };

    using vector_t     = etl::stack_vector<Counter, 2>;
    auto const counter = Counter(&currentCount);
    {
        auto vec = vector_t {1, counter};
        REQUIRE_FALSE(vec.empty());
    }
    REQUIRE(currentCount == 1);

    currentCount = 0;
    {
        auto vec = vector_t {2, counter};
        REQUIRE_FALSE(vec.empty());
    }
    REQUIRE(currentCount == 2);
}

TEMPLATE_TEST_CASE("stack_vector: assign", "[stack_vector]", int, float)
{
    using vector_t = etl::stack_vector<TestType, 2>;
    auto vec       = vector_t {};
    REQUIRE(vec.empty());

    vec.assign(1, TestType {});
    REQUIRE(vec.size() == 1);

    vec.assign(2, TestType {});
    REQUIRE(vec.size() == 2);
}

TEMPLATE_TEST_CASE("stack_vector: begin/end", "[stack_vector]", char, int,
                   float)
{
    using vector_t = etl::stack_vector<TestType, 16>;

    WHEN("vector is empty")
    {
        auto vec = vector_t {};
        REQUIRE(vec.empty());
        REQUIRE(vec.begin() == vec.end());
        REQUIRE(vec.cbegin() == vec.cend());
    }

    WHEN("vector is empty & const")
    {
        auto const vec = vector_t {};
        REQUIRE(vec.empty());
        REQUIRE(vec.begin() == vec.end());
        REQUIRE(vec.cbegin() == vec.cend());
    }
}

TEMPLATE_TEST_CASE("stack_vector: push_back", "[stack_vector]", char, int,
                   float)
{
    using vector_t = etl::stack_vector<TestType, 4>;
    auto vec       = vector_t {};

    SECTION("should increase size with each push_back")
    {
        REQUIRE(vec.empty());
        vec.push_back(TestType {});
        REQUIRE(vec.size() == 1);
        vec.push_back(TestType {});
        REQUIRE(vec.size() == 2);
        vec.push_back(TestType {});
        REQUIRE(vec.size() == 3);
        vec.push_back(TestType {});
        REQUIRE(vec.size() == 4);
    }

    SECTION("should throw when going over capacity")
    {
        vec.push_back(TestType {});
        vec.push_back(TestType {});
        vec.push_back(TestType {});
        vec.push_back(TestType {});
        REQUIRE(vec.size() == 4);
        REQUIRE(vec.size() == vec.capacity());
    }

    SECTION("should be empty again after clearing")
    {
        REQUIRE(vec.empty());

        vec.push_back(TestType {});
        vec.push_back(TestType {});
        vec.push_back(TestType {});
        vec.push_back(TestType {});
        REQUIRE(vec.size() == 4);

        vec.clear();
        REQUIRE(vec.empty());
    }
}

TEMPLATE_TEST_CASE("stack_vector: emplace_back", "[stack_vector]", char, int,
                   float)
{
    using vector_t = etl::stack_vector<TestType, 4>;
    auto vec       = vector_t {};

    SECTION("should increase size with each emplace_back")
    {
        REQUIRE(vec.empty());
        vec.emplace_back(TestType {1});
        REQUIRE(vec.size() == 1);
        REQUIRE(vec.back() == 1);
        vec.emplace_back(TestType {2});
        REQUIRE(vec.size() == 2);
        REQUIRE(vec.back() == 2);
        vec.emplace_back(TestType {1});
        REQUIRE(vec.size() == 3);
        vec.emplace_back(TestType {1});
        REQUIRE(vec.size() == 4);
    }

    SECTION("should throw when going over capacity")
    {
        vec.emplace_back(TestType {1});
        vec.emplace_back(TestType {1});
        vec.emplace_back(TestType {1});
        vec.emplace_back(TestType {1});
        REQUIRE(vec.size() == 4);
        REQUIRE(vec.size() == vec.capacity());
    }

    SECTION("should be empty again after clearing")
    {
        REQUIRE(vec.empty());

        vec.emplace_back(TestType {1});
        vec.emplace_back(TestType {1});
        vec.emplace_back(TestType {1});
        vec.emplace_back(TestType {1});
        REQUIRE(vec.size() == 4);

        vec.clear();
        REQUIRE(vec.empty());
    }
}

TEST_CASE("stack_vector: emplace_back - custom ctor", "[stack_vector]")
{
    struct Foo
    {
        Foo(int x, float y) : x_ {x}, y_ {y} { }
        int x_;
        float y_;
    };

    using vector_t = etl::stack_vector<Foo, 4>;
    auto vec       = vector_t {};

    SECTION("should increase size with each emplace_back")
    {
        REQUIRE(vec.empty());
        vec.emplace_back(143, 1.43f);
        REQUIRE(vec.size() == 1);
        vec.emplace_back(143, 1.43f);
        REQUIRE(vec.size() == 2);
        vec.emplace_back(143, 1.43f);
        REQUIRE(vec.size() == 3);
        vec.emplace_back(143, 1.43f);
        REQUIRE(vec.size() == 4);
    }

    SECTION("should throw when going over capacity")
    {
        vec.emplace_back(143, 1.43f);
        vec.emplace_back(143, 1.43f);
        vec.emplace_back(143, 1.43f);
        vec.emplace_back(143, 1.43f);
        REQUIRE(vec.size() == 4);
        REQUIRE(vec.size() == vec.capacity());
    }

    SECTION("should be empty again after clearing")
    {
        REQUIRE(vec.empty());

        vec.emplace_back(143, 1.43f);
        vec.emplace_back(143, 1.43f);
        vec.emplace_back(143, 1.43f);
        vec.emplace_back(143, 1.43f);
        REQUIRE(vec.size() == 4);

        vec.clear();
        REQUIRE(vec.empty());
    }
}

TEMPLATE_TEST_CASE("stack_vector: operator[]", "[stack_vector]", char, int,
                   float)
{
    using vector_t = etl::stack_vector<TestType, 4>;
    auto vec       = vector_t {};
    REQUIRE(vec.empty());
    vec.emplace_back(TestType {1});
    vec.emplace_back(TestType {2});

    REQUIRE(vec[0] == TestType {1});
    REQUIRE(vec[1] == TestType {2});

    auto const vec2 = vec;
    REQUIRE(vec2[0] == TestType {1});
    REQUIRE(vec2[1] == TestType {2});
}

TEMPLATE_TEST_CASE("stack_vector: at", "[stack_vector]", char, int, float)
{
    using vector_t = etl::stack_vector<TestType, 4>;
    auto vec       = vector_t {};
    REQUIRE(vec.empty());
    vec.emplace_back(TestType {1});
    vec.emplace_back(TestType {2});

    REQUIRE(vec.at(0) == TestType {1});
    REQUIRE(vec.at(1) == TestType {2});

    auto const vec2 = vec;
    REQUIRE(vec2.at(0) == TestType {1});
    REQUIRE(vec2.at(1) == TestType {2});
}

TEMPLATE_TEST_CASE("stack_vector: front/back", "[stack_vector]", char, int,
                   float)
{
    using vector_t = etl::stack_vector<TestType, 4>;
    auto vec       = vector_t {};
    REQUIRE(vec.empty());

    vec.emplace_back(TestType {1});
    REQUIRE(vec.front() == TestType {1});
    REQUIRE(vec.back() == TestType {1});
    REQUIRE(vec.front() == vec.back());

    vec.emplace_back(TestType {2});
    REQUIRE_FALSE(vec.front() == vec.back());
    REQUIRE(vec.front() == TestType {1});
    REQUIRE(vec.back() == TestType {2});

    auto const vec2 = vec;
    REQUIRE_FALSE(vec2.front() == vec2.back());
    REQUIRE(vec2.front() == TestType {1});
    REQUIRE(vec2.back() == TestType {2});
}

TEMPLATE_TEST_CASE("stack_vector: data", "[stack_vector]", char, int, float)
{
    using vector_t = etl::stack_vector<TestType, 4>;

    auto vec = vector_t {};
    REQUIRE(vec.empty());
    REQUIRE(vec.data() == vec.begin());

    auto const vec2 = vec;
    REQUIRE(vec2.data() == vec2.begin());
}

TEMPLATE_TEST_CASE("stack_vector: ranged-for", "[stack_vector]", char, int)
{
    using vector_t = etl::stack_vector<TestType, 4>;
    auto vec       = vector_t {};

    SECTION("loop")
    {
        vec.emplace_back(TestType {1});
        vec.emplace_back(TestType {1});
        vec.emplace_back(TestType {1});
        vec.emplace_back(TestType {1});

        auto sum = 0;
        for (auto const& element : vec) { sum += element; }
        REQUIRE(sum == 4);
    }

    SECTION("algorithm")
    {
        vec.emplace_back(TestType {1});
        vec.emplace_back(TestType {2});
        vec.emplace_back(TestType {3});
        vec.emplace_back(TestType {4});
        auto const sum = std::accumulate(std::begin(vec), std::end(vec), 0);
        REQUIRE(sum == 10);
    }
}