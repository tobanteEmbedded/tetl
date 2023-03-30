// SPDX-License-Identifier: BSL-1.0

#include "etl/type_traits.hpp"

#include "testing/testing.hpp"
#include "testing/types.hpp"

namespace {

struct A { };

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
    virtual ~IsPolymorphic_B() = default;
    virtual void foo() { }
};

struct IsPolymorphic_C : IsPolymorphic_B {
    ~IsPolymorphic_C() override = default;
};

struct IsPolymorphic_D {
    virtual ~IsPolymorphic_D() = default;
};

struct IsFinal_A {
    int m;
};

struct IsFinal_B {
    virtual ~IsFinal_B() = default;
    virtual void foo() { } // NOLINT
};

struct IsFinal_C final : IsFinal_B {
    ~IsFinal_C() override = default;
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
    virtual ~IsAbstract_B() = default;
    virtual void foo() { }
};

struct IsAbstract_C {
    virtual ~IsAbstract_C() = default;
    virtual void foo()      = 0;
};

struct IsAbstract_D : IsAbstract_C {
    ~IsAbstract_D() override = default;
};

} // namespace

constexpr auto test_all() -> bool
{
    using etl::make_signed_t;
    TEST_TRAIT_TYPE(make_signed, etl::int8_t, etl::int8_t);
    TEST_TRAIT_TYPE(make_signed, etl::int16_t, etl::int16_t);
    TEST_TRAIT_TYPE(make_signed, etl::int32_t, etl::int32_t);
    TEST_TRAIT_TYPE(make_signed, etl::int64_t, etl::int64_t);

    TEST_TRAIT_TYPE(make_signed, etl::uint8_t, etl::int8_t);
    TEST_TRAIT_TYPE(make_signed, etl::uint16_t, etl::int16_t);
    TEST_TRAIT_TYPE(make_signed, etl::uint32_t, etl::int32_t);
    TEST_TRAIT_TYPE(make_signed, etl::uint64_t, etl::int64_t);

    TEST_TRAIT_TYPE(make_signed, signed char, signed char);
    TEST_TRAIT_TYPE(make_signed, short, short);
    TEST_TRAIT_TYPE(make_signed, int, int);
    TEST_TRAIT_TYPE(make_signed, long, long);
    TEST_TRAIT_TYPE(make_signed, long long, long long);

    TEST_TRAIT_TYPE(make_signed, unsigned char, signed char);
    TEST_TRAIT_TYPE(make_signed, unsigned short, short);
    TEST_TRAIT_TYPE(make_signed, unsigned int, int);
    TEST_TRAIT_TYPE(make_signed, unsigned long, long);
    TEST_TRAIT_TYPE(make_signed, unsigned long long, long long);

    TEST_TRAIT_TYPE(make_unsigned, etl::int8_t, etl::uint8_t);
    TEST_TRAIT_TYPE(make_unsigned, etl::int16_t, etl::uint16_t);
    TEST_TRAIT_TYPE(make_unsigned, etl::int32_t, etl::uint32_t);
    TEST_TRAIT_TYPE(make_unsigned, etl::int64_t, etl::uint64_t);

    TEST_TRAIT_TYPE(make_unsigned, etl::uint8_t, etl::uint8_t);
    TEST_TRAIT_TYPE(make_unsigned, etl::uint16_t, etl::uint16_t);
    TEST_TRAIT_TYPE(make_unsigned, etl::uint32_t, etl::uint32_t);
    TEST_TRAIT_TYPE(make_unsigned, etl::uint64_t, etl::uint64_t);

    TEST_TRAIT_TYPE(make_unsigned, signed char, unsigned char);
    TEST_TRAIT_TYPE(make_unsigned, short, unsigned short);
    TEST_TRAIT_TYPE(make_unsigned, int, unsigned int);
    TEST_TRAIT_TYPE(make_unsigned, long, unsigned long);
    TEST_TRAIT_TYPE(make_unsigned, long long, unsigned long long);

    TEST_TRAIT_TYPE(make_unsigned, unsigned char, unsigned char);
    TEST_TRAIT_TYPE(make_unsigned, unsigned short, unsigned short);
    TEST_TRAIT_TYPE(make_unsigned, unsigned int, unsigned int);
    TEST_TRAIT_TYPE(make_unsigned, unsigned long, unsigned long);
    TEST_TRAIT_TYPE(make_unsigned, unsigned long long, unsigned long long);

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
