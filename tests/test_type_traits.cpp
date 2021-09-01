/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#include "etl/type_traits.hpp"

#include "etl/cstdint.hpp"
#include "etl/utility.hpp"
#include "etl/vector.hpp"

#include "catch2/catch_template_test_macros.hpp"

namespace {
struct A {
};

struct B {
    int m;
};

struct C {
    [[maybe_unused]] static int m;
};

struct D {
    virtual ~D() = default;
};

union E {
};

} // namespace

TEMPLATE_TEST_CASE(
    "type_traits: is_standard_layout = true", "[type_traits]", A, B, C, E)
{
    STATIC_REQUIRE(etl::is_standard_layout<TestType>::value);
    STATIC_REQUIRE(etl::is_standard_layout_v<TestType>);
}

TEMPLATE_TEST_CASE(
    "type_traits: is_standard_layout = false", "[type_traits]", D)
{
    STATIC_REQUIRE_FALSE(etl::is_standard_layout<TestType>::value);
    STATIC_REQUIRE_FALSE(etl::is_standard_layout_v<TestType>);
}

TEMPLATE_TEST_CASE("type_traits: is_empty = true", "[type_traits]", A, C)
{
    STATIC_REQUIRE(etl::is_empty<TestType>::value);
    STATIC_REQUIRE(etl::is_empty_v<TestType>);
}

TEMPLATE_TEST_CASE("type_traits: is_empty = false", "[type_traits]", B, D, E)
{
    STATIC_REQUIRE_FALSE(etl::is_empty<TestType>::value);
    STATIC_REQUIRE_FALSE(etl::is_empty_v<TestType>);
}

namespace {
struct IsPolymorphic_A {
    int m;
};

struct IsPolymorphic_B {
    virtual void foo();
};

struct IsPolymorphic_C : IsPolymorphic_B {
};

struct IsPolymorphic_D {
    virtual ~IsPolymorphic_D() = default;
};

} // namespace

TEMPLATE_TEST_CASE("type_traits: is_polymorphic = false", "[type_traits]", int,
    float, IsPolymorphic_A)
{
    STATIC_REQUIRE_FALSE(etl::is_polymorphic<TestType>::value);
    STATIC_REQUIRE_FALSE(etl::is_polymorphic_v<TestType>);
}

TEMPLATE_TEST_CASE("type_traits: is_polymorphic = true", "[type_traits]",
    IsPolymorphic_B, IsPolymorphic_C, IsPolymorphic_D)
{
    STATIC_REQUIRE(etl::is_polymorphic<TestType>::value);
    STATIC_REQUIRE(etl::is_polymorphic_v<TestType>);
}

namespace {
struct IsFinal_A {
    int m;
};

struct IsFinal_B {
    virtual void foo(); // NOLINT
};

struct IsFinal_C final : IsFinal_B {
};

struct IsFinal_D {
    virtual ~IsFinal_D() = default;
};

union IsFinal_E final {
    char data1;
    float data2;
};

} // namespace

TEMPLATE_TEST_CASE("type_traits: is_final = false", "[type_traits]", int, float,
    IsFinal_A, IsFinal_B, IsFinal_D)
{
    STATIC_REQUIRE_FALSE(etl::is_final<TestType>::value);
    STATIC_REQUIRE_FALSE(etl::is_final_v<TestType>);
}

TEMPLATE_TEST_CASE(
    "type_traits: is_final = true", "[type_traits]", IsFinal_C, IsFinal_E)
{
    STATIC_REQUIRE(etl::is_final<TestType>::value);
    STATIC_REQUIRE(etl::is_final_v<TestType>);
}

namespace {
struct IsAbstract_A {
    int m;
};

struct IsAbstract_B {
    virtual void foo() { }
};

struct IsAbstract_C {
    virtual void foo() = 0;
};

struct IsAbstract_D : IsAbstract_C {
};
} // namespace
TEMPLATE_TEST_CASE("type_traits: is_abstract = false", "[type_traits]", int,
    float, IsAbstract_A, IsAbstract_B)
{
    STATIC_REQUIRE_FALSE(etl::is_abstract<TestType>::value);
    STATIC_REQUIRE_FALSE(etl::is_abstract_v<TestType>);
}

TEMPLATE_TEST_CASE("type_traits: is_abstract = true", "[type_traits]",
    IsAbstract_C, IsAbstract_D)
{
    STATIC_REQUIRE(etl::is_abstract<TestType>::value);
    STATIC_REQUIRE(etl::is_abstract_v<TestType>);
}

TEMPLATE_TEST_CASE("type_traits: is_integral = false", "[type_traits]", float,
    double, long double, (struct S))
{
    STATIC_REQUIRE(etl::is_integral_v<TestType> == false);
}

TEMPLATE_TEST_CASE("type_traits: is_integral = true", "[type_traits]",
    etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
    etl::int32_t, etl::uint64_t, etl::int64_t)
{
    STATIC_REQUIRE(etl::is_integral_v<TestType>);
}

TEMPLATE_TEST_CASE("type_traits: is_floating_point = true", "[type_traits]",
    float, double, long double)
{
    STATIC_REQUIRE(etl::is_floating_point_v<TestType>);
}

TEMPLATE_TEST_CASE("type_traits: is_floating_point = false", "[type_traits]",
    etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
    etl::int32_t, etl::uint64_t, etl::int64_t, (struct S))
{
    STATIC_REQUIRE(etl::is_floating_point_v<TestType> == false);
}

TEMPLATE_TEST_CASE("type_traits: is_null_pointer = false", "[type_traits]",
    etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
    etl::int32_t, etl::uint64_t, etl::int64_t, float, double, long double,
    struct S)
{
    STATIC_REQUIRE(etl::is_null_pointer_v<TestType> == false);
}

TEST_CASE("type_traits: is_null_pointer = true", "[type_traits]")
{
    STATIC_REQUIRE(etl::is_null_pointer_v<decltype(nullptr)>);
}

TEMPLATE_TEST_CASE("type_traits: is_array = false", "[type_traits]",
    etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
    etl::int32_t, etl::uint64_t, etl::int64_t, float, double, long double)
{
    STATIC_REQUIRE(etl::is_array_v<TestType> == false);
}

TEMPLATE_TEST_CASE("type_traits: is_array = true", "[type_traits]",
    etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
    etl::int32_t, etl::uint64_t, etl::int64_t, float, double, long double)
{
    STATIC_REQUIRE(etl::is_array_v<TestType[]>);
    STATIC_REQUIRE(etl::is_array_v<TestType[4]>);
}

TEMPLATE_TEST_CASE("type_traits: is_pointer", "[type_traits]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    STATIC_REQUIRE(etl::is_pointer_v<TestType*>);
    STATIC_REQUIRE(etl::is_pointer_v<TestType> == false);
}

// TODO: Fix MSVC compilation.
#if not defined(TETL_MSVC)

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

TEMPLATE_TEST_CASE("type_traits: is_lvalue_reference", "[type_traits]",
    etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
    etl::int32_t, etl::uint64_t, etl::int64_t, float, double, long double)
{
    STATIC_REQUIRE(etl::is_lvalue_reference_v<TestType&>);
    STATIC_REQUIRE(etl::is_lvalue_reference_v<TestType const&>);

    STATIC_REQUIRE_FALSE(etl::is_lvalue_reference<TestType>::value);
    STATIC_REQUIRE_FALSE(etl::is_lvalue_reference<TestType const>::value);
    STATIC_REQUIRE_FALSE(etl::is_lvalue_reference<TestType*>::value);
    STATIC_REQUIRE_FALSE(etl::is_lvalue_reference<TestType const*>::value);
    STATIC_REQUIRE_FALSE(etl::is_lvalue_reference<TestType&&>::value);
}

// TODO: Fix on MSVC. Compiles but emits warnings
#if not defined(TETL_MSVC)

TEMPLATE_TEST_CASE("type_traits: is_member_function_pointer", "[type_traits]",
    etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
    etl::int32_t, etl::uint64_t, etl::int64_t, float, double, long double)
{
    using etl::is_member_function_pointer_v;

    class CA {
    public:
        void memberF() { }   // NOLINT
        TestType memberV {}; // NOLINT
    };

    struct SA {
    public:
        void memberF() { }   // NOLINT
        TestType memberV {}; // NOLINT
    };

    STATIC_REQUIRE_FALSE(is_member_function_pointer_v<decltype(&CA::memberV)>);
    STATIC_REQUIRE(is_member_function_pointer_v<decltype(&CA::memberF)>);

    STATIC_REQUIRE_FALSE(is_member_function_pointer_v<decltype(&SA::memberV)>);
    STATIC_REQUIRE(is_member_function_pointer_v<decltype(&SA::memberF)>);
}

TEMPLATE_TEST_CASE("type_traits: is_member_pointer", "[type_traits]",
    etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
    etl::int32_t, etl::uint64_t, etl::int64_t, float, double, long double)
{
    using etl::is_member_pointer_v;

    class Cls {
    };

    STATIC_REQUIRE(is_member_pointer_v<TestType(Cls::*)>);
    STATIC_REQUIRE_FALSE(is_member_pointer_v<TestType>);
}

#endif

TEMPLATE_TEST_CASE(
    "type_traits: is_class = true", "[type_traits]", struct S, struct CS)
{
    STATIC_REQUIRE(etl::is_class_v<TestType>);
    STATIC_REQUIRE(etl::is_class_v<struct X>);
}

enum Enum {
    one,
};

enum class EnumC {
    nop,
};

TEMPLATE_TEST_CASE("type_traits: is_enum = true", "[type_traits]", Enum, EnumC)
{
    STATIC_REQUIRE(etl::is_enum_v<TestType>);
    STATIC_REQUIRE(etl::is_enum_v<TestType const>);
    STATIC_REQUIRE(etl::is_enum_v<TestType volatile>);
}

using UnionA = union {
    double b;
    int a;
};

using UnionB = union {
    int a;
    float b;
};

TEMPLATE_TEST_CASE(
    "type_traits: is_union = true", "[type_traits]", UnionA, UnionB)
{
    STATIC_REQUIRE(etl::is_union_v<TestType>);
    STATIC_REQUIRE(etl::is_union_v<TestType const>);
    STATIC_REQUIRE(etl::is_union_v<TestType volatile>);
}

TEMPLATE_TEST_CASE("type_traits: is_compound = true", "[type_traits]",
    struct StructIsCompound, class ClassIsCompound, union UnionIsCompound)
{
    STATIC_REQUIRE(etl::is_compound<TestType>::value);
    STATIC_REQUIRE(etl::is_compound_v<TestType>);
    STATIC_REQUIRE(etl::is_compound_v<TestType*>);
    STATIC_REQUIRE(etl::is_compound_v<TestType&>);
}

TEMPLATE_TEST_CASE("type_traits: is_reference", "[type_traits]", bool,
    etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
    etl::int32_t, etl::uint64_t, etl::int64_t, float, double, long double,
    struct ReferenceToStruct, class ReferenceToClass, union ReferenceToUnion)
{
}

TEMPLATE_TEST_CASE("type_traits: is_fundamental", "[type_traits]", bool,
    etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
    etl::int32_t, etl::uint64_t, etl::int64_t, float, double, long double)
{
    struct S {
        TestType data;
    };
}

class A {
};
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

TEMPLATE_TEST_CASE("type_traits: is_bounded_array", "[type_traits]",
    etl::uint8_t, etl::uint16_t, etl::uint32_t, etl::uint64_t, etl::int8_t,
    etl::int16_t, etl::int32_t, etl::int64_t, float, double, long double, A, B,
    C)
{
}

TEMPLATE_TEST_CASE("type_traits: is_unbounded_array", "[type_traits]",
    etl::uint8_t, etl::uint16_t, etl::uint32_t, etl::uint64_t, etl::int8_t,
    etl::int16_t, etl::int32_t, etl::int64_t, float, double, long double, A, B,
    C)
{
}

TEMPLATE_TEST_CASE("type_traits: is_constructible", "[type_traits]",
    etl::uint8_t, etl::uint16_t, etl::uint32_t, etl::uint64_t, etl::int8_t,
    etl::int16_t, etl::int32_t, etl::int64_t, float, double, long double, A, B,
    C)
{
    STATIC_REQUIRE(etl::is_constructible_v<TestType>);
    STATIC_REQUIRE(etl::is_constructible_v<TestType*>);
    STATIC_REQUIRE(etl::is_constructible_v<TestType, TestType&>);
    STATIC_REQUIRE(etl::is_constructible_v<TestType, TestType const&>);

    STATIC_REQUIRE_FALSE(etl::is_constructible_v<TestType&>);
    STATIC_REQUIRE_FALSE(etl::is_constructible_v<TestType const&>);

    class Foo {
        TestType v1; // NOLINT
        double v2;   // NOLINT

    public:
        Foo(TestType n) : v1(n), v2() { }
        Foo(TestType n, double f) noexcept : v1(n), v2(f) { }
    };

    STATIC_REQUIRE(etl::is_constructible_v<Foo, TestType>);
    STATIC_REQUIRE(etl::is_constructible_v<Foo, TestType, double>);
    STATIC_REQUIRE_FALSE(etl::is_constructible_v<Foo, TestType, struct S>);
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

TEMPLATE_TEST_CASE("type_traits: add_rvalue_reference", "[type_traits]",
    etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
    etl::int32_t, etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T   = TestType;
    using CT  = TestType const;
    using VT  = TestType volatile;
    using CVT = TestType const volatile;

    using etl::add_rvalue_reference_t;
    using etl::is_same_v;

    STATIC_REQUIRE(is_same_v<add_rvalue_reference_t<T>, T&&>);
    STATIC_REQUIRE(is_same_v<add_rvalue_reference_t<CT>, CT&&>);
    STATIC_REQUIRE(is_same_v<add_rvalue_reference_t<VT>, VT&&>);
    STATIC_REQUIRE(is_same_v<add_rvalue_reference_t<CVT>, CVT&&>);
}

TEMPLATE_TEST_CASE("type_traits: add_cv", "[type_traits]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;
    using etl::add_cv_t;
    using etl::is_same_v;

    STATIC_REQUIRE(is_same_v<add_cv_t<T>, T const volatile>);
    STATIC_REQUIRE(is_same_v<add_cv_t<T const>, T const volatile>);
    STATIC_REQUIRE(is_same_v<add_cv_t<T volatile>, T const volatile>);
    STATIC_REQUIRE(is_same_v<add_cv_t<T const volatile>, T const volatile>);
}

TEMPLATE_TEST_CASE("type_traits: add_const", "[type_traits]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;
    using etl::add_const_t;
    using etl::is_same_v;

    STATIC_REQUIRE(is_same_v<add_const_t<T>, T const>);
    STATIC_REQUIRE(is_same_v<add_const_t<T const>, T const>);
    STATIC_REQUIRE(is_same_v<add_const_t<T volatile>, T const volatile>);
    STATIC_REQUIRE(is_same_v<add_const_t<T const volatile>, T const volatile>);
}

TEMPLATE_TEST_CASE("type_traits: add_volatile", "[type_traits]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;
    using etl::add_volatile_t;
    using etl::is_same_v;

    STATIC_REQUIRE(is_same_v<add_volatile_t<T>, T volatile>);
    STATIC_REQUIRE(is_same_v<add_volatile_t<T const>, T const volatile>);
    STATIC_REQUIRE(is_same_v<add_volatile_t<T volatile>, T volatile>);
    STATIC_REQUIRE(
        is_same_v<add_volatile_t<T const volatile>, T const volatile>);
}

TEST_CASE("type_traits: conditional", "[type_traits]")
{
    using etl::conditional;
    using etl::conditional_t;
    using Type1 = conditional<true, int, double>::type;
    using Type2 = conditional<false, int, double>::type;

    // true
    REQUIRE(typeid(Type1) == typeid(int));
    REQUIRE(typeid(Type2) == typeid(double));
    REQUIRE(typeid(conditional_t<false, int, double>) == typeid(double));

    // false
    REQUIRE_FALSE(typeid(Type1) == typeid(double));
    REQUIRE_FALSE(typeid(Type2) == typeid(int));
}

TEST_CASE("type_traits: conjunction", "[type_traits]")
{
    using etl::conjunction_v;
    using etl::is_same;

    STATIC_REQUIRE(conjunction_v<is_same<int, int>, is_same<short, short>>);
    STATIC_REQUIRE(conjunction_v<is_same<short, short>, is_same<float, float>>);
    STATIC_REQUIRE(conjunction_v<is_same<int, int>, is_same<double, double>>);

    STATIC_REQUIRE_FALSE(
        conjunction_v<is_same<float, int>, is_same<char, char>>);
    STATIC_REQUIRE_FALSE(
        conjunction_v<is_same<int, short>, is_same<char, char>>);
    STATIC_REQUIRE_FALSE(
        conjunction_v<is_same<int, int>, is_same<char, float>>);
}

TEST_CASE("type_traits: disjunction", "[type_traits]")
{
    using etl::disjunction_v;
    using etl::is_same;

    STATIC_REQUIRE(disjunction_v<is_same<int, int>, is_same<short, short>>);
    STATIC_REQUIRE(disjunction_v<is_same<short, short>, is_same<float, float>>);
    STATIC_REQUIRE(disjunction_v<is_same<int, int>, is_same<double, double>>);

    STATIC_REQUIRE(disjunction_v<is_same<float, int>, is_same<short, short>>);
    STATIC_REQUIRE(disjunction_v<is_same<int, short>, is_same<float, float>>);
    STATIC_REQUIRE(disjunction_v<is_same<int, int>, is_same<double, float>>);

    STATIC_REQUIRE_FALSE(
        disjunction_v<is_same<char, int>, is_same<short, char>>);
    STATIC_REQUIRE_FALSE(
        disjunction_v<is_same<int, short>, is_same<float, int>>);
    STATIC_REQUIRE_FALSE(
        disjunction_v<is_same<bool, int>, is_same<char, float>>);
}

TEST_CASE("type_traits: negation", "[type_traits]")
{
    STATIC_REQUIRE(etl::negation_v<etl::is_same<short, float>>);
    STATIC_REQUIRE(etl::negation_v<etl::is_same<bool, float>>);
    STATIC_REQUIRE(etl::negation_v<etl::is_same<int, float>>);

    STATIC_REQUIRE_FALSE(etl::negation_v<etl::is_same<int, int>>);
    STATIC_REQUIRE_FALSE(etl::negation_v<etl::is_same<bool, bool>>);
    STATIC_REQUIRE_FALSE(etl::negation_v<etl::is_same<float, float>>);
}

TEMPLATE_TEST_CASE("type_traits: rank", "[type_traits]", bool, etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    STATIC_REQUIRE(etl::rank<TestType>::value == 0);
    STATIC_REQUIRE(etl::rank_v<TestType> == 0);

    STATIC_REQUIRE(etl::rank<TestType[5]>::value == 1);
    STATIC_REQUIRE(etl::rank<TestType[5][5]>::value == 2);
    STATIC_REQUIRE(etl::rank<TestType[][5][5]>::value == 3);
}

TEMPLATE_TEST_CASE("type_traits: remove_extent", "[type_traits]", bool,
    etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
    etl::int32_t, etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;
    using etl::is_same_v;
    using etl::remove_extent_t;

    STATIC_REQUIRE(is_same_v<remove_extent_t<T>, T>);
    STATIC_REQUIRE(is_same_v<remove_extent_t<T*>, T*>);
    STATIC_REQUIRE(is_same_v<remove_extent_t<T&>, T&>);
    STATIC_REQUIRE(is_same_v<remove_extent_t<T const>, T const>);
    STATIC_REQUIRE(is_same_v<remove_extent_t<T[]>, T>);
    STATIC_REQUIRE(is_same_v<remove_extent_t<T[1]>, T>);
    STATIC_REQUIRE(is_same_v<remove_extent_t<T[16]>, T>);
    STATIC_REQUIRE(is_same_v<remove_extent_t<T[1][2]>, T[2]>);
    STATIC_REQUIRE(is_same_v<remove_extent_t<T[1][2][3]>, T[2][3]>);
}

TEMPLATE_TEST_CASE("type_traits: remove_all_extents", "[type_traits]", bool,
    etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
    etl::int32_t, etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;
    using etl::is_same_v;
    using etl::remove_all_extents_t;

    STATIC_REQUIRE(is_same_v<remove_all_extents_t<T>, T>);
    STATIC_REQUIRE(is_same_v<remove_all_extents_t<T*>, T*>);
    STATIC_REQUIRE(is_same_v<remove_all_extents_t<T&>, T&>);
    STATIC_REQUIRE(is_same_v<remove_all_extents_t<T const>, T const>);
    STATIC_REQUIRE(is_same_v<remove_all_extents_t<T[]>, T>);
    STATIC_REQUIRE(is_same_v<remove_all_extents_t<T[1]>, T>);
    STATIC_REQUIRE(is_same_v<remove_all_extents_t<T[16]>, T>);
    STATIC_REQUIRE(is_same_v<remove_all_extents_t<T[1][2]>, T>);
    STATIC_REQUIRE(is_same_v<remove_all_extents_t<T[1][2][3]>, T>);
}

TEMPLATE_TEST_CASE("type_traits: decay", "[type_traits]", bool, etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;
    using etl::decay_t;
    using etl::is_same_v;

    STATIC_REQUIRE(is_same_v<decay_t<T>, T>);
    STATIC_REQUIRE(is_same_v<decay_t<T&>, T>);
    STATIC_REQUIRE(is_same_v<decay_t<T&&>, T>);
    STATIC_REQUIRE(is_same_v<decay_t<T const&>, T>);
    STATIC_REQUIRE(is_same_v<decay_t<T[2]>, T*>);

    // TODO: Broken on MSVC
    //  STATIC_REQUIRE(is_same_v<decay_t<T(T)>, T (*)(T)>);
}

TEMPLATE_TEST_CASE("type_traits: common_type", "[type_traits]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double)
{
    using T = TestType;
    using etl::common_type_t;
    using etl::is_same_v;

    STATIC_REQUIRE(is_same_v<common_type_t<T>, T>);
    STATIC_REQUIRE(is_same_v<common_type_t<T, T>, T>);
    STATIC_REQUIRE(is_same_v<common_type_t<T, T const>, T>);
    STATIC_REQUIRE(is_same_v<common_type_t<T, T volatile>, T>);
    STATIC_REQUIRE(is_same_v<common_type_t<T, T const volatile>, T>);

    STATIC_REQUIRE(is_same_v<common_type_t<T, double>, double>);
}

TEMPLATE_TEST_CASE("type_traits: conjunction", "[type_traits]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double)
{
    using T = TestType;
    using etl::conjunction_v;
    using etl::is_same;

    STATIC_REQUIRE(conjunction_v<etl::true_type>);
    STATIC_REQUIRE(conjunction_v<etl::true_type, etl::true_type>);
    STATIC_REQUIRE_FALSE(conjunction_v<etl::false_type>);

    STATIC_REQUIRE(conjunction_v<is_same<T, T>, is_same<T const, T const>>);
    STATIC_REQUIRE_FALSE(conjunction_v<is_same<T, T>, etl::false_type>);
}

TEMPLATE_TEST_CASE("type_traits: disjunction", "[type_traits]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double)
{
    using T = TestType;
    using etl::disjunction_v;
    using etl::is_same;

    STATIC_REQUIRE_FALSE(disjunction_v<etl::false_type>);
    STATIC_REQUIRE_FALSE(disjunction_v<etl::false_type, etl::false_type>);

    STATIC_REQUIRE(disjunction_v<etl::true_type>);
    STATIC_REQUIRE(disjunction_v<etl::true_type, etl::true_type>);
    STATIC_REQUIRE(disjunction_v<etl::true_type, etl::false_type>);

    STATIC_REQUIRE(disjunction_v<is_same<T, T>, is_same<T const, T const>>);
    STATIC_REQUIRE(disjunction_v<is_same<T, T>, etl::false_type>);
}

TEST_CASE("type_traits: make_signed", "[type_traits]")
{
    using etl::is_same_v;
    using etl::make_signed_t;

    STATIC_REQUIRE(is_same_v<make_signed_t<int8_t>, int8_t>);
    STATIC_REQUIRE(is_same_v<make_signed_t<int16_t>, int16_t>);
    STATIC_REQUIRE(is_same_v<make_signed_t<int32_t>, int32_t>);
    STATIC_REQUIRE(is_same_v<make_signed_t<int64_t>, int64_t>);

    STATIC_REQUIRE(is_same_v<make_signed_t<uint8_t>, int8_t>);
    STATIC_REQUIRE(is_same_v<make_signed_t<uint16_t>, int16_t>);
    STATIC_REQUIRE(is_same_v<make_signed_t<uint32_t>, int32_t>);
    STATIC_REQUIRE(is_same_v<make_signed_t<uint64_t>, int64_t>);

    STATIC_REQUIRE(is_same_v<make_signed_t<signed char>, signed char>);
    STATIC_REQUIRE(is_same_v<make_signed_t<short>, short>);
    STATIC_REQUIRE(is_same_v<make_signed_t<int>, int>);
    STATIC_REQUIRE(is_same_v<make_signed_t<long>, long>);
    STATIC_REQUIRE(is_same_v<make_signed_t<long long>, long long>);

    STATIC_REQUIRE(is_same_v<make_signed_t<unsigned char>, signed char>);
    STATIC_REQUIRE(is_same_v<make_signed_t<unsigned short>, short>);
    STATIC_REQUIRE(is_same_v<make_signed_t<unsigned int>, int>);
    STATIC_REQUIRE(is_same_v<make_signed_t<unsigned long>, long>);
    STATIC_REQUIRE(is_same_v<make_signed_t<unsigned long long>, long long>);
}

TEST_CASE("type_traits: make_unsigned", "[type_traits]")
{
    using etl::is_same_v;
    using etl::make_unsigned_t;

    // clang-format off
    STATIC_REQUIRE(is_same_v<make_unsigned_t<int8_t>, uint8_t>);
    STATIC_REQUIRE(is_same_v<make_unsigned_t<int16_t>, uint16_t>);
    STATIC_REQUIRE(is_same_v<make_unsigned_t<int32_t>, uint32_t>);
    STATIC_REQUIRE(is_same_v<make_unsigned_t<int64_t>, uint64_t>);

    STATIC_REQUIRE(is_same_v<make_unsigned_t<uint8_t>, uint8_t>);
    STATIC_REQUIRE(is_same_v<make_unsigned_t<uint16_t>, uint16_t>);
    STATIC_REQUIRE(is_same_v<make_unsigned_t<uint32_t>, uint32_t>);
    STATIC_REQUIRE(is_same_v<make_unsigned_t<uint64_t>, uint64_t>);

    STATIC_REQUIRE(is_same_v<make_unsigned_t<signed char>, unsigned char>);
    STATIC_REQUIRE(is_same_v<make_unsigned_t<short>, unsigned short>);
    STATIC_REQUIRE(is_same_v<make_unsigned_t<int>, unsigned int>);
    STATIC_REQUIRE(is_same_v<make_unsigned_t<long>, unsigned long>);
    STATIC_REQUIRE(is_same_v<make_unsigned_t<long long>, unsigned long long>);

    STATIC_REQUIRE(is_same_v<make_unsigned_t<unsigned char>, unsigned char>);
    STATIC_REQUIRE(is_same_v<make_unsigned_t<unsigned short>, unsigned short>);
    STATIC_REQUIRE(is_same_v<make_unsigned_t<unsigned int>, unsigned int>);
    STATIC_REQUIRE(is_same_v<make_unsigned_t<unsigned long>, unsigned long>);
    STATIC_REQUIRE(is_same_v<make_unsigned_t<unsigned long long>, unsigned long long>);
    // clang-format on
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

TEMPLATE_TEST_CASE("type_traits: underlying_type", "[type_traits]", char, short,
    int, long, unsigned, unsigned long)
{
    using etl::is_same_v;
    using etl::underlying_type;
    using etl::underlying_type_t;

    enum CEnum : TestType { foobar };

    enum struct EnumStruct : TestType { a, b, c };

    enum class EnumClass : TestType {
        x,
        y,
    };

    STATIC_REQUIRE(is_same_v<TestType, typename underlying_type<CEnum>::type>);
    STATIC_REQUIRE(is_same_v<TestType, underlying_type_t<EnumStruct>>);
    STATIC_REQUIRE(is_same_v<TestType, underlying_type_t<EnumClass>>);
}

TEMPLATE_TEST_CASE("type_traits: is_scoped_enum", "[type_traits]", char, short,
    int, long, unsigned, unsigned long)
{
    class SomeClass {
    };

    enum CEnum : TestType {};

    enum struct Es { oz };

    enum class Ec : TestType {};

    STATIC_REQUIRE_FALSE(etl::is_scoped_enum_v<TestType>);
    STATIC_REQUIRE_FALSE(etl::is_scoped_enum<SomeClass>::value);
    STATIC_REQUIRE_FALSE(etl::is_scoped_enum<CEnum>::value);

    STATIC_REQUIRE(etl::is_scoped_enum<Es>::value);
    STATIC_REQUIRE(etl::is_scoped_enum_v<Ec>);
}

TEMPLATE_TEST_CASE("type_traits: aligned_union", "[type_traits]", bool,
    etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
    etl::int32_t, etl::uint64_t, etl::int64_t, float, double)
{
    using T = TestType;

    STATIC_REQUIRE(sizeof(etl::aligned_union_t<0, char>) == 1);
    STATIC_REQUIRE(sizeof(etl::aligned_union_t<2, char>) == 2);
    STATIC_REQUIRE(sizeof(etl::aligned_union_t<2, char[3]>) == 3);
    STATIC_REQUIRE(sizeof(etl::aligned_union_t<3, char[4]>) == 4);
    STATIC_REQUIRE(sizeof(etl::aligned_union_t<1, char, T, double>) == 8);
    STATIC_REQUIRE(sizeof(etl::aligned_union_t<12, char, T, double>) == 16);
}

TEMPLATE_TEST_CASE("type_traits: is_swappable", "[type_traits]", bool,
    etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
    etl::int32_t, etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;
    using etl::is_swappable_v;

    STATIC_REQUIRE(is_swappable_v<T>);

    STATIC_REQUIRE(is_swappable_v<T*>);
    STATIC_REQUIRE(is_swappable_v<T const*>);
    STATIC_REQUIRE(is_swappable_v<T volatile*>);
    STATIC_REQUIRE(is_swappable_v<T const volatile*>);

    STATIC_REQUIRE(is_swappable_v<void*>);
    STATIC_REQUIRE(is_swappable_v<void const*>);
    STATIC_REQUIRE(is_swappable_v<void volatile*>);
    STATIC_REQUIRE(is_swappable_v<void const volatile*>);
}

TEMPLATE_TEST_CASE("type_traits: is_swappable_with", "[type_traits]",
    etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
    etl::int32_t, etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;
    using etl::is_swappable_with_v;

    STATIC_REQUIRE(is_swappable_with_v<T&, T&>);
}

TEMPLATE_TEST_CASE("type_traits: has_virtual_destructor", "[type_traits]", bool,
    etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
    etl::int32_t, etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;
    using etl::has_virtual_destructor_v;

    STATIC_REQUIRE_FALSE(has_virtual_destructor_v<T>);
    STATIC_REQUIRE_FALSE(has_virtual_destructor_v<T const>);
    STATIC_REQUIRE_FALSE(has_virtual_destructor_v<T volatile>);
    STATIC_REQUIRE_FALSE(has_virtual_destructor_v<T const volatile>);

    STATIC_REQUIRE_FALSE(has_virtual_destructor_v<T&>);
    STATIC_REQUIRE_FALSE(has_virtual_destructor_v<T const&>);
    STATIC_REQUIRE_FALSE(has_virtual_destructor_v<T volatile&>);
    STATIC_REQUIRE_FALSE(has_virtual_destructor_v<T const volatile&>);

    STATIC_REQUIRE_FALSE(has_virtual_destructor_v<T*>);
    STATIC_REQUIRE_FALSE(has_virtual_destructor_v<T const*>);
    STATIC_REQUIRE_FALSE(has_virtual_destructor_v<T volatile*>);
    STATIC_REQUIRE_FALSE(has_virtual_destructor_v<T const volatile*>);

    struct NVS {
        ~NVS() { } // NOLINT
        TestType value {};
    };

    struct VS {
        virtual ~VS() { } // NOLINT
        TestType value {};
    };

    class NVC {
    public:
        ~NVC() { } // NOLINT
        TestType value {};
    };

    class VC {
    public:
        virtual ~VC() { } // NOLINT
        TestType value {};
    };

    STATIC_REQUIRE_FALSE(has_virtual_destructor_v<NVS>);
    STATIC_REQUIRE_FALSE(has_virtual_destructor_v<NVS const>);
    STATIC_REQUIRE_FALSE(has_virtual_destructor_v<NVS volatile>);
    STATIC_REQUIRE_FALSE(has_virtual_destructor_v<NVS const volatile>);

    STATIC_REQUIRE_FALSE(has_virtual_destructor_v<NVC>);
    STATIC_REQUIRE_FALSE(has_virtual_destructor_v<NVC const>);
    STATIC_REQUIRE_FALSE(has_virtual_destructor_v<NVC volatile>);
    STATIC_REQUIRE_FALSE(has_virtual_destructor_v<NVC const volatile>);

    STATIC_REQUIRE(has_virtual_destructor_v<VS>);
    STATIC_REQUIRE(has_virtual_destructor_v<VS const>);
    STATIC_REQUIRE(has_virtual_destructor_v<VS volatile>);
    STATIC_REQUIRE(has_virtual_destructor_v<VS const volatile>);

    STATIC_REQUIRE(has_virtual_destructor_v<VC>);
    STATIC_REQUIRE(has_virtual_destructor_v<VC const>);
    STATIC_REQUIRE(has_virtual_destructor_v<VC volatile>);
    STATIC_REQUIRE(has_virtual_destructor_v<VC const volatile>);
}

TEMPLATE_TEST_CASE("type_traits: is_copy_constructible", "[type_traits]", bool,
    etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
    etl::int32_t, etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;
    using etl::is_copy_constructible_v;

    STATIC_REQUIRE(is_copy_constructible_v<T>);
    STATIC_REQUIRE(is_copy_constructible_v<T&>);
    STATIC_REQUIRE(is_copy_constructible_v<T const&>);
    STATIC_REQUIRE(is_copy_constructible_v<T volatile&>);
    STATIC_REQUIRE(is_copy_constructible_v<T const volatile&>);

    struct CopyableS {
        TestType value {};
    };

    class CopyableC {
    public:
        TestType value {};
    };

    struct NonCopyableS {
        NonCopyableS(NonCopyableS const&) = delete; // NOLINT
        TestType value {};
    };

    class NonCopyableC {
    public:
        NonCopyableC(NonCopyableC const&) = delete; // NOLINT
        TestType value {};
    };

    STATIC_REQUIRE(is_copy_constructible_v<CopyableS>);
    STATIC_REQUIRE(is_copy_constructible_v<CopyableS const>);
    STATIC_REQUIRE_FALSE(is_copy_constructible_v<CopyableS volatile>);
    STATIC_REQUIRE_FALSE(is_copy_constructible_v<CopyableS const volatile>);

    STATIC_REQUIRE(is_copy_constructible_v<CopyableC>);
    STATIC_REQUIRE(is_copy_constructible_v<CopyableC const>);
    STATIC_REQUIRE_FALSE(is_copy_constructible_v<CopyableC volatile>);
    STATIC_REQUIRE_FALSE(is_copy_constructible_v<CopyableC const volatile>);

    STATIC_REQUIRE_FALSE(is_copy_constructible_v<NonCopyableS>);
    STATIC_REQUIRE_FALSE(is_copy_constructible_v<NonCopyableS const>);
    STATIC_REQUIRE_FALSE(is_copy_constructible_v<NonCopyableS volatile>);
    STATIC_REQUIRE_FALSE(is_copy_constructible_v<NonCopyableS const volatile>);

    STATIC_REQUIRE_FALSE(is_copy_constructible_v<NonCopyableC>);
    STATIC_REQUIRE_FALSE(is_copy_constructible_v<NonCopyableC const>);
    STATIC_REQUIRE_FALSE(is_copy_constructible_v<NonCopyableC volatile>);
    STATIC_REQUIRE_FALSE(is_copy_constructible_v<NonCopyableC const volatile>);
}

TEMPLATE_TEST_CASE("type_traits: is_trivially_copy_constructible",
    "[type_traits]", bool, etl::uint8_t, etl::int8_t, etl::uint16_t,
    etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
    float, double, long double)
{
    using T = TestType;
    using etl::is_trivially_copy_constructible_v;

    STATIC_REQUIRE(is_trivially_copy_constructible_v<T>);

    STATIC_REQUIRE(is_trivially_copy_constructible_v<T*>);
    STATIC_REQUIRE(is_trivially_copy_constructible_v<T const*>);
    STATIC_REQUIRE(is_trivially_copy_constructible_v<T volatile*>);
    STATIC_REQUIRE(is_trivially_copy_constructible_v<T const volatile*>);

    STATIC_REQUIRE_FALSE(is_trivially_copy_constructible_v<T&>);
    STATIC_REQUIRE_FALSE(is_trivially_copy_constructible_v<T const&>);
    STATIC_REQUIRE_FALSE(is_trivially_copy_constructible_v<T volatile&>);
    STATIC_REQUIRE_FALSE(is_trivially_copy_constructible_v<T const volatile&>);

    struct TCS {
    };

    class TCC {
    public:
        TestType value;
    };

    STATIC_REQUIRE(is_trivially_copy_constructible_v<TCS>);
    STATIC_REQUIRE(is_trivially_copy_constructible_v<TCS const>);
    STATIC_REQUIRE(is_trivially_copy_constructible_v<TCS volatile>);
    STATIC_REQUIRE(is_trivially_copy_constructible_v<TCS const volatile>);

    STATIC_REQUIRE(is_trivially_copy_constructible_v<TCC>);
    STATIC_REQUIRE(is_trivially_copy_constructible_v<TCC const>);
    STATIC_REQUIRE(is_trivially_copy_constructible_v<TCC volatile>);
    STATIC_REQUIRE(is_trivially_copy_constructible_v<TCC const volatile>);
}

namespace detail {
struct trivial_type {
};

} // namespace detail

TEMPLATE_TEST_CASE("type_traits: is_trivial", "[type_traits]", bool,
    etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
    etl::int32_t, etl::uint64_t, etl::int64_t, float, double, long double,
    detail::trivial_type)
{
    using T = TestType;

    // STATIC_REQUIRE(etl::is_trivial_v<T>);
    // STATIC_REQUIRE(etl::is_trivial_v<T const>);
    // STATIC_REQUIRE(etl::is_trivial_v<T volatile>);
    // STATIC_REQUIRE(etl::is_trivial_v<T const volatile>);

    STATIC_REQUIRE(etl::is_trivial_v<T*>);
    STATIC_REQUIRE(etl::is_trivial_v<T const*>);
    STATIC_REQUIRE(etl::is_trivial_v<T volatile*>);
    STATIC_REQUIRE(etl::is_trivial_v<T const volatile*>);

    STATIC_REQUIRE_FALSE(etl::is_trivial_v<T&>);
    STATIC_REQUIRE_FALSE(etl::is_trivial_v<T const&>);
    STATIC_REQUIRE_FALSE(etl::is_trivial_v<T volatile&>);
    STATIC_REQUIRE_FALSE(etl::is_trivial_v<T const volatile&>);

    struct non_trivial_type {
        non_trivial_type() { } // NOLINT
    };

    STATIC_REQUIRE_FALSE(etl::is_trivial_v<non_trivial_type>);
    STATIC_REQUIRE_FALSE(etl::is_trivial_v<non_trivial_type const>);
    STATIC_REQUIRE_FALSE(etl::is_trivial_v<non_trivial_type volatile>);
    STATIC_REQUIRE_FALSE(etl::is_trivial_v<non_trivial_type const volatile>);
}

TEMPLATE_TEST_CASE("type_traits: is_trivially_copyable", "[type_traits]", bool,
    etl::uint8_t, etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t,
    etl::int32_t, etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;
    using etl::is_trivially_copyable_v;

    STATIC_REQUIRE(is_trivially_copyable_v<T>);
    STATIC_REQUIRE(is_trivially_copyable_v<T*>);

    struct TCA { // NOLINT
        int m;
    };

    struct TCB { // NOLINT
        TCB(TCB const& /*ignore*/) { }
    };

    struct TCD { // NOLINT
        TCD(TCD const& /*ignore*/) = default;
        TCD(int x) : m(x + 1) { }
        int m;
    };

    STATIC_REQUIRE(etl::is_trivially_copyable<TCA>::value);
    STATIC_REQUIRE(etl::is_trivially_copyable<TCD>::value);

    STATIC_REQUIRE_FALSE(etl::is_trivially_copyable<TCB>::value);
}

TEMPLATE_TEST_CASE("type_traits: invoke_result", "[type_traits]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;

    struct S {
        auto operator()(char /*unused*/, int& /*unused*/) -> T { return T(2); }
        auto operator()(int /*unused*/) -> float { return 1.0F; }
    };

    STATIC_REQUIRE(etl::is_same_v<etl::invoke_result_t<S, char, int&>, T>);
    STATIC_REQUIRE(etl::is_same_v<etl::invoke_result_t<S, int>, float>);
}

TEMPLATE_TEST_CASE("type_traits: is_invocable", "[type_traits]", etl::uint8_t,
    etl::int8_t, etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t,
    etl::uint64_t, etl::int64_t, float, double, long double)
{
    using T = TestType;
    STATIC_REQUIRE(etl::is_invocable_v<T()>);
    STATIC_REQUIRE(!etl::is_invocable_v<T(), T>);
}

namespace {
[[nodiscard]] auto func2(char /*ignore*/) -> int (*)() { return nullptr; }
} // namespace

TEMPLATE_TEST_CASE("type_traits: is_invocable_r", "[type_traits]",
    etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t,
    etl::int64_t, float, double, long double)
{
    using T = TestType;

    STATIC_REQUIRE(etl::is_invocable_r_v<T, T()>);
    STATIC_REQUIRE(!etl::is_invocable_r_v<T*, T()>);
    STATIC_REQUIRE(etl::is_invocable_r_v<void, void(T), T>);
    STATIC_REQUIRE(!etl::is_invocable_r_v<void, void(T), void>);
    STATIC_REQUIRE(etl::is_invocable_r_v<int (*)(), decltype(func2), char>);
    STATIC_REQUIRE(!etl::is_invocable_r_v<T (*)(), decltype(func2), void>);
    etl::ignore_unused(func2);
}

namespace {

template <typename T>
constexpr auto test_identity() -> bool
{
    using etl::is_same_v;
    using etl::type_identity;
    using etl::type_identity_t;

    static_assert(is_same_v<T, typename type_identity<T>::type>);
    static_assert(is_same_v<T, type_identity_t<T>>);

    // clang-format off
    if constexpr (!etl::is_function_v<T>) {
        static_assert(is_same_v<T const, typename type_identity<T const>::type>);
        static_assert(is_same_v<T volatile, typename type_identity<T volatile>::type>);
        static_assert(is_same_v<T const volatile, typename type_identity<T const volatile>::type>);

        static_assert(is_same_v<T const, type_identity_t<T const>>);
        static_assert(is_same_v<T volatile, type_identity_t<T volatile>>);
        static_assert(is_same_v<T const volatile, type_identity_t<T const volatile>>);
    }

    if constexpr (!etl::is_void_v<T>) {
        static_assert(is_same_v<T&, typename type_identity<T&>::type>);
        static_assert(is_same_v<T&&, typename type_identity<T&&>::type>);

        static_assert(is_same_v<T&, type_identity_t<T&>>);
        static_assert(is_same_v<T&&, type_identity_t<T&&>>);
    }

    if constexpr (!etl::is_void_v<T> && !etl::is_function_v<T>) {
        static_assert(is_same_v<T const&, typename type_identity<T const&>::type>);
        static_assert(is_same_v<T volatile&, typename type_identity<T volatile&>::type>);
        static_assert(is_same_v<T const volatile&, typename type_identity<T const volatile&>::type>);
        static_assert(is_same_v<T const&&, typename type_identity<T const&&>::type>);
        static_assert(is_same_v<T volatile&&, typename type_identity<T volatile&&>::type>);
        static_assert(is_same_v<T const volatile&&, typename type_identity<T const volatile&&>::type>);

        static_assert(is_same_v<T const&, type_identity_t<T const&>>);
        static_assert(is_same_v<T volatile&, type_identity_t<T volatile&>>);
        static_assert(is_same_v<T const volatile&, type_identity_t<T const volatile&>>);
        static_assert(is_same_v<T const&&, type_identity_t<T const&&>>);
        static_assert(is_same_v<T volatile&&, type_identity_t<T volatile&&>>);
        static_assert(is_same_v<T const volatile&&, type_identity_t<T const volatile&&>>);
    }

    // clang-format on
    return true;
}
struct IDS {
};
} // namespace

TEMPLATE_TEST_CASE("type_traits: type_identity", "[type_traits]", etl::uint16_t,
    etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t, etl::int64_t,
    float, double, long double)
{
    using T = TestType;

    // clang-format off
    STATIC_REQUIRE(test_identity<void>());
    STATIC_REQUIRE(test_identity<T>());
    STATIC_REQUIRE(test_identity<T*>());
    STATIC_REQUIRE(test_identity<T const*>());
    STATIC_REQUIRE(test_identity<T volatile*>());
    STATIC_REQUIRE(test_identity<T const volatile*>());
    STATIC_REQUIRE(test_identity<T[3]>());
    STATIC_REQUIRE(test_identity<T[]>());
    STATIC_REQUIRE(test_identity<T(T)>());
    STATIC_REQUIRE(test_identity<T&(T)>());
    STATIC_REQUIRE(test_identity<T const&(T)>());
    STATIC_REQUIRE(test_identity<T volatile&(T)>());
    STATIC_REQUIRE(test_identity<T const volatile&(T)>());
    STATIC_REQUIRE(test_identity<T(T&)>());
    STATIC_REQUIRE(test_identity<T(T const&)>());
    STATIC_REQUIRE(test_identity<T(T volatile&)>());
    STATIC_REQUIRE(test_identity<T(T const volatile&)>());
    STATIC_REQUIRE(test_identity<T IDS::*>());
    STATIC_REQUIRE(test_identity<T const IDS::*>());
    STATIC_REQUIRE(test_identity<T volatile IDS::*>());
    STATIC_REQUIRE(test_identity<T const volatile IDS::*>());
    STATIC_REQUIRE(test_identity<T (IDS::*)(T)>());
    STATIC_REQUIRE(test_identity<T (IDS::*)(T&)>());
    STATIC_REQUIRE(test_identity<T (IDS::*)(T const&) const>());
    STATIC_REQUIRE(test_identity<T (IDS::*)(T volatile&) volatile>());
    STATIC_REQUIRE(test_identity<T (IDS::*)(T const volatile&) const volatile>());
    STATIC_REQUIRE(test_identity<T (IDS::*)(T)&>());
    STATIC_REQUIRE(test_identity<T (IDS::*)(T) const&>());
    STATIC_REQUIRE(test_identity<T (IDS::*)(T) &&>());
    STATIC_REQUIRE(test_identity<T (IDS::*)(T) const&&>());
    STATIC_REQUIRE(test_identity<T& (IDS::*)(T)>());
    STATIC_REQUIRE(test_identity<T const& (IDS::*)(T)>());
    STATIC_REQUIRE(test_identity<T volatile& (IDS::*)(T)>());
    STATIC_REQUIRE(test_identity<T const volatile& (IDS::*)(T)>());
    // clang-format on
}

TEMPLATE_TEST_CASE("type_traits: type_pack_element_t", "[type_traits]",
    etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t,
    etl::int64_t, float, double, long double)
{
    using T = TestType;
    using etl::is_same_v;
    using etl::type_pack_element_t;

    STATIC_REQUIRE(is_same_v<type_pack_element_t<0, T>, T>);
    STATIC_REQUIRE(is_same_v<type_pack_element_t<1, T, float>, float>);
    STATIC_REQUIRE(is_same_v<type_pack_element_t<2, T, char, short>, short>);
}

namespace {
template <typename T>
struct test_is_specialized;

template <>
struct test_is_specialized<float> {
};

struct not_specialized {
};
} // namespace

TEMPLATE_TEST_CASE("type_traits: is_specialized", "[type_traits]",
    etl::uint16_t, etl::int16_t, etl::uint32_t, etl::int32_t, etl::uint64_t,
    etl::int64_t, not_specialized)
{
    using T = TestType;

    STATIC_REQUIRE(etl::is_specialized_v<test_is_specialized, float>);
    STATIC_REQUIRE_FALSE(etl::is_specialized_v<test_is_specialized, T>);
    STATIC_REQUIRE_FALSE(etl::is_specialized_v<test_is_specialized, double>);
}
