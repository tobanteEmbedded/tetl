// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"
#include "testing/types.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl.cstddef;
import etl.cstdint;
import etl.type_traits;
#else
    #include <etl/cstddef.hpp>
    #include <etl/cstdint.hpp>
    #include <etl/type_traits.hpp>
#endif

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

static constexpr auto test_all() -> bool
{
    CHECK_TRAIT_TYPE(make_signed, etl::int8_t, etl::int8_t);
    CHECK_TRAIT_TYPE(make_signed, etl::int16_t, etl::int16_t);
    CHECK_TRAIT_TYPE(make_signed, etl::int32_t, etl::int32_t);
    CHECK_TRAIT_TYPE(make_signed, etl::int64_t, etl::int64_t);

    CHECK_TRAIT_TYPE(make_signed, etl::uint8_t, etl::int8_t);
    CHECK_TRAIT_TYPE(make_signed, etl::uint16_t, etl::int16_t);
    CHECK_TRAIT_TYPE(make_signed, etl::uint32_t, etl::int32_t);
    CHECK_TRAIT_TYPE(make_signed, etl::uint64_t, etl::int64_t);

    CHECK_TRAIT_TYPE(make_signed, signed char, signed char);
    CHECK_TRAIT_TYPE(make_signed, short, short);
    CHECK_TRAIT_TYPE(make_signed, int, int);
    CHECK_TRAIT_TYPE(make_signed, long, long);
    CHECK_TRAIT_TYPE(make_signed, long long, long long);

    CHECK_TRAIT_TYPE(make_signed, unsigned char, signed char);
    CHECK_TRAIT_TYPE(make_signed, unsigned short, short);
    CHECK_TRAIT_TYPE(make_signed, unsigned int, int);
    CHECK_TRAIT_TYPE(make_signed, unsigned long, long);
    CHECK_TRAIT_TYPE(make_signed, unsigned long long, long long);

    CHECK_TRAIT_TYPE(make_unsigned, etl::int8_t, etl::uint8_t);
    CHECK_TRAIT_TYPE(make_unsigned, etl::int16_t, etl::uint16_t);
    CHECK_TRAIT_TYPE(make_unsigned, etl::int32_t, etl::uint32_t);
    CHECK_TRAIT_TYPE(make_unsigned, etl::int64_t, etl::uint64_t);

    CHECK_TRAIT_TYPE(make_unsigned, etl::uint8_t, etl::uint8_t);
    CHECK_TRAIT_TYPE(make_unsigned, etl::uint16_t, etl::uint16_t);
    CHECK_TRAIT_TYPE(make_unsigned, etl::uint32_t, etl::uint32_t);
    CHECK_TRAIT_TYPE(make_unsigned, etl::uint64_t, etl::uint64_t);

    CHECK_TRAIT_TYPE(make_unsigned, signed char, unsigned char);
    CHECK_TRAIT_TYPE(make_unsigned, short, unsigned short);
    CHECK_TRAIT_TYPE(make_unsigned, int, unsigned int);
    CHECK_TRAIT_TYPE(make_unsigned, long, unsigned long);
    CHECK_TRAIT_TYPE(make_unsigned, long long, unsigned long long);

    CHECK_TRAIT_TYPE(make_unsigned, unsigned char, unsigned char);
    CHECK_TRAIT_TYPE(make_unsigned, unsigned short, unsigned short);
    CHECK_TRAIT_TYPE(make_unsigned, unsigned int, unsigned int);
    CHECK_TRAIT_TYPE(make_unsigned, unsigned long, unsigned long);
    CHECK_TRAIT_TYPE(make_unsigned, unsigned long long, unsigned long long);

    CHECK_IS_TRAIT_CV(is_standard_layout, A);
    CHECK_IS_TRAIT_CV(is_standard_layout, B);
    CHECK_IS_TRAIT_CV(is_standard_layout, C);
    CHECK_IS_TRAIT_CV(is_standard_layout, E);
    CHECK_IS_TRAIT_CV_FALSE(is_standard_layout, D);

    CHECK_IS_TRAIT_CV(is_empty, A);
    CHECK_IS_TRAIT_CV(is_empty, C);
    CHECK_IS_TRAIT_CV_FALSE(is_empty, B);
    CHECK_IS_TRAIT_CV_FALSE(is_empty, D);
    CHECK_IS_TRAIT_CV_FALSE(is_empty, E);

    CHECK_IS_TRAIT_CV(is_polymorphic, IsPolymorphic_B);
    CHECK_IS_TRAIT_CV(is_polymorphic, IsPolymorphic_C);
    CHECK_IS_TRAIT_CV(is_polymorphic, IsPolymorphic_D);
    CHECK_IS_TRAIT_CV_FALSE(is_polymorphic, int);
    CHECK_IS_TRAIT_CV_FALSE(is_polymorphic, IsPolymorphic_A);

    CHECK_IS_TRAIT_CV(is_final, IsFinal_C);
    CHECK_IS_TRAIT_CV(is_final, IsFinal_E);
    CHECK_IS_TRAIT_CV_FALSE(is_final, int);
    CHECK_IS_TRAIT_CV_FALSE(is_final, float);
    CHECK_IS_TRAIT_CV_FALSE(is_final, IsFinal_A);
    CHECK_IS_TRAIT_CV_FALSE(is_final, IsFinal_B);
    CHECK_IS_TRAIT_CV_FALSE(is_final, IsFinal_D);

    CHECK_IS_TRAIT_CV(is_abstract, IsAbstract_C);
    CHECK_IS_TRAIT_CV(is_abstract, IsAbstract_D);
    CHECK_IS_TRAIT_CV_FALSE(is_abstract, int);
    CHECK_IS_TRAIT_CV_FALSE(is_abstract, float);
    CHECK_IS_TRAIT_CV_FALSE(is_abstract, IsAbstract_A);
    CHECK_IS_TRAIT_CV_FALSE(is_abstract, IsAbstract_B);

    CHECK_IS_TRAIT_CV(is_integral, char);
    CHECK_IS_TRAIT_CV(is_integral, unsigned char);
    CHECK_IS_TRAIT_CV(is_integral, signed char);
    CHECK_IS_TRAIT_CV(is_integral, unsigned short);
    CHECK_IS_TRAIT_CV(is_integral, signed short);
    CHECK_IS_TRAIT_CV(is_integral, unsigned int);
    CHECK_IS_TRAIT_CV(is_integral, signed int);
    CHECK_IS_TRAIT_CV(is_integral, unsigned long);
    CHECK_IS_TRAIT_CV(is_integral, signed long);
    CHECK_IS_TRAIT_CV(is_integral, unsigned long long);
    CHECK_IS_TRAIT_CV(is_integral, signed long long);
    CHECK_IS_TRAIT_CV_FALSE(is_integral, float);
    CHECK_IS_TRAIT_CV_FALSE(is_integral, double);
    CHECK_IS_TRAIT_CV_FALSE(is_integral, long double);
    CHECK_IS_TRAIT_CV_FALSE(is_integral, struct NotIntegral);
    CHECK_IS_TRAIT_CV_FALSE(is_integral, etl::nullptr_t);

    CHECK_IS_TRAIT_CV(is_floating_point, float);
    CHECK_IS_TRAIT_CV(is_floating_point, double);
    CHECK_IS_TRAIT_CV(is_floating_point, long double);
    CHECK_IS_TRAIT_CV_FALSE(is_floating_point, char);
    CHECK_IS_TRAIT_CV_FALSE(is_floating_point, unsigned char);
    CHECK_IS_TRAIT_CV_FALSE(is_floating_point, signed char);
    CHECK_IS_TRAIT_CV_FALSE(is_floating_point, unsigned short);
    CHECK_IS_TRAIT_CV_FALSE(is_floating_point, signed short);
    CHECK_IS_TRAIT_CV_FALSE(is_floating_point, unsigned int);
    CHECK_IS_TRAIT_CV_FALSE(is_floating_point, signed int);
    CHECK_IS_TRAIT_CV_FALSE(is_floating_point, unsigned long);
    CHECK_IS_TRAIT_CV_FALSE(is_floating_point, signed long);
    CHECK_IS_TRAIT_CV_FALSE(is_floating_point, unsigned long long);
    CHECK_IS_TRAIT_CV_FALSE(is_floating_point, signed long long);
    CHECK_IS_TRAIT_CV_FALSE(is_floating_point, etl::nullptr_t);

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
