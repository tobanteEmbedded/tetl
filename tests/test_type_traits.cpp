/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#include "etl/type_traits.hpp"

#include "etl/cstdint.hpp"
#include "etl/utility.hpp"
#include "etl/vector.hpp"

#include "catch2/catch_template_test_macros.hpp"

// TODO: Fix MSVC compilation.
#if not defined(TETL_MSVC)

struct A {
};

struct AAA {
    int fun() const&; // NOLINT
};

template <typename>
struct PM_traits {
};

template <class T, class U>
struct PM_traits<U T::*> {
    using member_type = U;
};

int f(); // NOLINT

TEST_CASE("type_traits: is_function", "[type_traits]")
{
    SECTION("cppreference.com example")
    {
        using T
            = PM_traits<decltype(&AAA::fun)>::member_type; // T is int() const&

        STATIC_REQUIRE_FALSE(etl::is_function_v<A>);
        STATIC_REQUIRE(etl::is_function_v<decltype(f)>);
        STATIC_REQUIRE_FALSE(etl::is_function_v<int>);
        STATIC_REQUIRE(etl::is_function_v<T>);
    }
}

#endif

enum B : unsigned {};
enum class C : unsigned {};

TEMPLATE_TEST_CASE("type_traits: is_unsigned = false", "[type_traits]",
    etl::int8_t, etl::int16_t, etl::int32_t, etl::int64_t, float, double,
    long double, A, B, C)
{
    STATIC_REQUIRE_FALSE(etl::is_unsigned<TestType>::value);
    STATIC_REQUIRE_FALSE(etl::is_unsigned_v<TestType>);
}

TEMPLATE_TEST_CASE("type_traits: is_unsigned = true", "[type_traits]",
    etl::uint8_t, etl::uint16_t, etl::uint32_t, etl::uint64_t)
{
    STATIC_REQUIRE(etl::is_unsigned<TestType>::value);
}

TEMPLATE_TEST_CASE("type_traits: is_signed = true", "[type_traits]",
    etl::int8_t, etl::int16_t, etl::int32_t, etl::int64_t, float, double,
    long double)
{
    STATIC_REQUIRE(etl::is_signed<TestType>::value);
    STATIC_REQUIRE(etl::is_signed_v<TestType>);
}

TEMPLATE_TEST_CASE("type_traits: is_signed = false", "[type_traits]",
    etl::uint8_t, etl::uint16_t, etl::uint32_t, etl::uint64_t, A, B, C)
{
    STATIC_REQUIRE_FALSE(etl::is_signed<TestType>::value);
}

TEMPLATE_TEST_CASE("type_traits: is_nothrow_constructible", "[type_traits]",
    etl::uint8_t, etl::uint16_t, etl::uint32_t, etl::uint64_t, etl::int8_t,
    etl::int16_t, etl::int32_t, etl::int64_t, float, double, long double, A, B,
    C)
{
    using etl::is_nothrow_constructible_v;

    STATIC_REQUIRE(is_nothrow_constructible_v<TestType>);
    STATIC_REQUIRE(is_nothrow_constructible_v<TestType*>);
    STATIC_REQUIRE(is_nothrow_constructible_v<TestType, TestType&>);
    STATIC_REQUIRE(is_nothrow_constructible_v<TestType, TestType const&>);

    STATIC_REQUIRE_FALSE(is_nothrow_constructible_v<TestType&>);
    STATIC_REQUIRE_FALSE(is_nothrow_constructible_v<TestType const&>);

    class Foo {
        TestType v1; // NOLINT
        double v2;   // NOLINT

    public:
        Foo(TestType n) : v1(n), v2() { }
        Foo(TestType n, double f) noexcept : v1(n), v2(f) { }
    };

    STATIC_REQUIRE(is_nothrow_constructible_v<Foo, TestType, double>);
    STATIC_REQUIRE_FALSE(is_nothrow_constructible_v<Foo, TestType>);
}

TEMPLATE_TEST_CASE("type_traits: is_trivially_constructible", "[type_traits]",
    etl::uint8_t, etl::uint16_t, etl::uint32_t, etl::uint64_t, etl::int8_t,
    etl::int16_t, etl::int32_t, etl::int64_t, float, double, long double, A, B,
    C)
{
    using etl::is_trivially_constructible_v;

    STATIC_REQUIRE(is_trivially_constructible_v<TestType>);
    STATIC_REQUIRE(is_trivially_constructible_v<TestType*>);
    STATIC_REQUIRE(is_trivially_constructible_v<TestType, TestType&>);
    STATIC_REQUIRE(is_trivially_constructible_v<TestType, TestType const&>);

    STATIC_REQUIRE_FALSE(is_trivially_constructible_v<TestType&>);
    STATIC_REQUIRE_FALSE(is_trivially_constructible_v<TestType const&>);

    class Foo {
        TestType v1; // NOLINT
        double v2;   // NOLINT

    public:
        Foo(TestType n) : v1(n), v2() { }
        Foo(TestType n, double f) noexcept : v1(n), v2(f) { }
    };

    STATIC_REQUIRE_FALSE(is_trivially_constructible_v<Foo, TestType, double>);
    STATIC_REQUIRE_FALSE(is_trivially_constructible_v<Foo, TestType>);
}

TEMPLATE_TEST_CASE("type_traits: alignment_of = 1", "[type_traits]",
    etl::uint8_t, etl::int8_t, char)
{
    STATIC_REQUIRE(etl::alignment_of_v<TestType> == 1);
}

TEMPLATE_TEST_CASE("type_traits: alignment_of = 1", "[type_traits]",
    etl::int16_t, etl::uint16_t, short, char16_t)
{
    STATIC_REQUIRE(etl::alignment_of_v<TestType> == 2);
}

namespace {

struct Ex2 {
    // trivial and non-throwing
    Ex2() = default;
    int n;
};

struct Ex3 {
    Ex3(int& n) : ref { n } { }

    int& ref;
};

} // namespace

TEMPLATE_TEST_CASE(
    "type_traits: is_default_constructible", "[type_traits]", int, float, Ex2)
{
    STATIC_REQUIRE(etl::is_default_constructible<TestType>::value);
    STATIC_REQUIRE(etl::is_default_constructible_v<TestType>);

    STATIC_REQUIRE_FALSE(etl::is_default_constructible_v<Ex3>);
}

TEMPLATE_TEST_CASE("type_traits: is_trivially_default_constructible",
    "[type_traits]", int, float, Ex2)
{
    STATIC_REQUIRE(etl::is_trivially_default_constructible<TestType>::value);
    STATIC_REQUIRE(etl::is_trivially_default_constructible_v<TestType>);

    STATIC_REQUIRE_FALSE(etl::is_trivially_default_constructible_v<Ex3>);
}

TEMPLATE_TEST_CASE("type_traits: is_nothrow_default_constructible",
    "[type_traits]", int, float, Ex2)
{
    STATIC_REQUIRE(etl::is_nothrow_default_constructible<TestType>::value);
    STATIC_REQUIRE(etl::is_nothrow_default_constructible_v<TestType>);
}

struct TrivialDtor_1 {
};

struct TrivialDtor_2 {
    ~TrivialDtor_2() = default;
};

struct NonTrivialDtor_1 {
    ~NonTrivialDtor_1() { }
};

struct NonTrivialDtor_2 {
    etl::static_vector<NonTrivialDtor_1, 16> data;
};

TEMPLATE_TEST_CASE("type_traits: is_trivially_destructible(true)",
    "[type_traits]", bool, etl::uint8_t, etl::int8_t, etl::uint16_t,
    etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
    float, double, long double, TrivialDtor_1, TrivialDtor_2)
{
    STATIC_REQUIRE(etl::is_trivially_destructible<TestType>::value);
    STATIC_REQUIRE(etl::is_trivially_destructible_v<TestType>);
}

TEMPLATE_TEST_CASE("type_traits: is_trivially_destructible(false)",
    "[type_traits]", NonTrivialDtor_1, NonTrivialDtor_2)
{
    STATIC_REQUIRE_FALSE(etl::is_trivially_destructible<TestType>::value);
    STATIC_REQUIRE_FALSE(etl::is_trivially_destructible_v<TestType>);
}
