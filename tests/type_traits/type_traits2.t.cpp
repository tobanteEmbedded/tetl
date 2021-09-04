/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/type_traits.hpp"

#include "testing.hpp"
#include "types.hpp"

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

constexpr auto test_all() -> bool
{
    TEST_IS_TRAIT_CV(is_standard_layout, A);
    TEST_IS_TRAIT_CV(is_standard_layout, B);
    TEST_IS_TRAIT_CV(is_standard_layout, C);
    TEST_IS_TRAIT_CV(is_standard_layout, E);
    TEST_IS_TRAIT_CV_FALSE(is_standard_layout, D);

    TEST_IS_TRAIT_CV(is_empty, A);
    TEST_IS_TRAIT_CV(is_empty, C);
    TEST_IS_TRAIT_CV_FALSE(is_empty, B);
    TEST_IS_TRAIT_CV_FALSE(is_empty, D);
    TEST_IS_TRAIT_CV_FALSE(is_empty, E);

    TEST_IS_TRAIT_CV(is_polymorphic, IsPolymorphic_B);
    TEST_IS_TRAIT_CV(is_polymorphic, IsPolymorphic_C);
    TEST_IS_TRAIT_CV(is_polymorphic, IsPolymorphic_D);
    TEST_IS_TRAIT_CV_FALSE(is_polymorphic, int);
    TEST_IS_TRAIT_CV_FALSE(is_polymorphic, IsPolymorphic_A);

    TEST_IS_TRAIT_CV(is_final, IsFinal_C);
    TEST_IS_TRAIT_CV(is_final, IsFinal_E);
    TEST_IS_TRAIT_CV_FALSE(is_final, int);
    TEST_IS_TRAIT_CV_FALSE(is_final, float);
    TEST_IS_TRAIT_CV_FALSE(is_final, IsFinal_A);
    TEST_IS_TRAIT_CV_FALSE(is_final, IsFinal_B);
    TEST_IS_TRAIT_CV_FALSE(is_final, IsFinal_D);

    TEST_IS_TRAIT_CV(is_abstract, IsAbstract_C);
    TEST_IS_TRAIT_CV(is_abstract, IsAbstract_D);
    TEST_IS_TRAIT_CV_FALSE(is_abstract, int);
    TEST_IS_TRAIT_CV_FALSE(is_abstract, float);
    TEST_IS_TRAIT_CV_FALSE(is_abstract, IsAbstract_A);
    TEST_IS_TRAIT_CV_FALSE(is_abstract, IsAbstract_B);

    TEST_IS_TRAIT_CV(is_integral, char);
    TEST_IS_TRAIT_CV(is_integral, unsigned char);
    TEST_IS_TRAIT_CV(is_integral, signed char);
    TEST_IS_TRAIT_CV(is_integral, unsigned short);
    TEST_IS_TRAIT_CV(is_integral, signed short);
    TEST_IS_TRAIT_CV(is_integral, unsigned int);
    TEST_IS_TRAIT_CV(is_integral, signed int);
    TEST_IS_TRAIT_CV(is_integral, unsigned long);
    TEST_IS_TRAIT_CV(is_integral, signed long);
    TEST_IS_TRAIT_CV(is_integral, unsigned long long);
    TEST_IS_TRAIT_CV(is_integral, signed long long);
    TEST_IS_TRAIT_CV_FALSE(is_integral, float);
    TEST_IS_TRAIT_CV_FALSE(is_integral, double);
    TEST_IS_TRAIT_CV_FALSE(is_integral, long double);
    TEST_IS_TRAIT_CV_FALSE(is_integral, struct NotIntegral);
    TEST_IS_TRAIT_CV_FALSE(is_integral, etl::nullptr_t);

    TEST_IS_TRAIT_CV(is_floating_point, float);
    TEST_IS_TRAIT_CV(is_floating_point, double);
    TEST_IS_TRAIT_CV(is_floating_point, long double);
    TEST_IS_TRAIT_CV_FALSE(is_floating_point, char);
    TEST_IS_TRAIT_CV_FALSE(is_floating_point, unsigned char);
    TEST_IS_TRAIT_CV_FALSE(is_floating_point, signed char);
    TEST_IS_TRAIT_CV_FALSE(is_floating_point, unsigned short);
    TEST_IS_TRAIT_CV_FALSE(is_floating_point, signed short);
    TEST_IS_TRAIT_CV_FALSE(is_floating_point, unsigned int);
    TEST_IS_TRAIT_CV_FALSE(is_floating_point, signed int);
    TEST_IS_TRAIT_CV_FALSE(is_floating_point, unsigned long);
    TEST_IS_TRAIT_CV_FALSE(is_floating_point, signed long);
    TEST_IS_TRAIT_CV_FALSE(is_floating_point, unsigned long long);
    TEST_IS_TRAIT_CV_FALSE(is_floating_point, signed long long);
    TEST_IS_TRAIT_CV_FALSE(is_floating_point, etl::nullptr_t);

    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}