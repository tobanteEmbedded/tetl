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
    // using T = TestType;

    // STATIC_REQUIRE(etl::is_trivial_v<T>);
    // STATIC_REQUIRE(etl::is_trivial_v<T const>);
    // STATIC_REQUIRE(etl::is_trivial_v<T volatile>);
    // STATIC_REQUIRE(etl::is_trivial_v<T const volatile>);

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
