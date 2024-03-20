// SPDX-License-Identifier: BSL-1.0

#include <etl/type_traits.hpp>

#include <etl/cstdint.hpp>

#include "testing/testing.hpp"
#include "testing/types.hpp"

#if not defined(TETL_WORKAROUND_AVR_BROKEN_TESTS)

template <typename T>
constexpr auto test() -> bool
{
    TEST_IS_TRAIT(is_member_pointer, PointerToMemberFunc);
    TEST_IS_TRAIT(is_member_pointer, PointerToConstMemberFunc);
    TEST_IS_TRAIT(is_member_pointer, PointerToVolatileMemberFunc);
    TEST_IS_TRAIT(is_member_pointer, PointerToCVMemberFunc);
    TEST_IS_TRAIT(is_member_pointer, PointerToMemberObj);
    TEST_IS_TRAIT(is_member_pointer, PointerToConstMemberObj);
    TEST_IS_TRAIT(is_member_pointer, PointerToVolatileMemberObj);
    TEST_IS_TRAIT(is_member_pointer, PointerToCVMemberObj);
    TEST_IS_TRAIT_CV_FALSE(is_member_pointer, T);
    TEST_IS_TRAIT_CV_FALSE(is_member_pointer, T*);

    TEST_IS_TRAIT(is_member_function_pointer, PointerToMemberFunc);
    TEST_IS_TRAIT(is_member_function_pointer, PointerToConstMemberFunc);
    TEST_IS_TRAIT(is_member_function_pointer, PointerToVolatileMemberFunc);
    TEST_IS_TRAIT(is_member_function_pointer, PointerToCVMemberFunc);
    TEST_IS_TRAIT_FALSE(is_member_function_pointer, PointerToMemberObj);
    TEST_IS_TRAIT_FALSE(is_member_function_pointer, PointerToConstMemberObj);
    TEST_IS_TRAIT_FALSE(is_member_function_pointer, PointerToVolatileMemberObj);
    TEST_IS_TRAIT_FALSE(is_member_function_pointer, PointerToCVMemberObj);
    TEST_IS_TRAIT_CV_FALSE(is_member_function_pointer, T);
    TEST_IS_TRAIT_CV_FALSE(is_member_function_pointer, T*);

    TEST_IS_TRAIT(is_member_object_pointer, PointerToMemberObj);
    TEST_IS_TRAIT(is_member_object_pointer, PointerToConstMemberObj);
    TEST_IS_TRAIT(is_member_object_pointer, PointerToVolatileMemberObj);
    TEST_IS_TRAIT(is_member_object_pointer, PointerToCVMemberObj);
    TEST_IS_TRAIT_FALSE(is_member_object_pointer, PointerToMemberFunc);
    TEST_IS_TRAIT_FALSE(is_member_object_pointer, PointerToConstMemberFunc);
    TEST_IS_TRAIT_FALSE(is_member_object_pointer, PointerToVolatileMemberFunc);
    TEST_IS_TRAIT_FALSE(is_member_object_pointer, PointerToCVMemberFunc);
    TEST_IS_TRAIT_CV_FALSE(is_member_object_pointer, T);
    TEST_IS_TRAIT_CV_FALSE(is_member_object_pointer, T*);

    TEST_IS_TRAIT_CV(is_enum, Enum);
    TEST_IS_TRAIT_CV(is_enum, EnumWithType);
    TEST_IS_TRAIT_CV(is_enum, ScopedEnum);
    TEST_IS_TRAIT_CV(is_enum, ScopedEnumWithType);
    TEST_IS_TRAIT_CV_FALSE(is_enum, EmptyClass);
    TEST_IS_TRAIT_CV_FALSE(is_enum, EmptyUnion);
    TEST_IS_TRAIT_CV_FALSE(is_enum, Abstract);
    TEST_IS_TRAIT_CV_FALSE(is_enum, T);

    TEST_IS_TRAIT_CV(is_union, EmptyUnion);
    TEST_IS_TRAIT_CV(is_union, DummyUnion);
    TEST_IS_TRAIT_CV_FALSE(is_union, Enum);
    TEST_IS_TRAIT_CV_FALSE(is_union, EnumWithType);
    TEST_IS_TRAIT_CV_FALSE(is_union, ScopedEnum);
    TEST_IS_TRAIT_CV_FALSE(is_union, ScopedEnumWithType);
    TEST_IS_TRAIT_CV_FALSE(is_union, EmptyClass);
    TEST_IS_TRAIT_CV_FALSE(is_union, DummyClass);
    TEST_IS_TRAIT_CV_FALSE(is_union, Abstract);
    TEST_IS_TRAIT_CV_FALSE(is_union, T);

    TEST_IS_TRAIT_CV(is_class, EmptyClass);
    TEST_IS_TRAIT_CV(is_class, DummyClass);
    TEST_IS_TRAIT_CV(is_class, Abstract);
    TEST_IS_TRAIT_CV_FALSE(is_class, Enum);
    TEST_IS_TRAIT_CV_FALSE(is_class, EnumWithType);
    TEST_IS_TRAIT_CV_FALSE(is_class, ScopedEnum);
    TEST_IS_TRAIT_CV_FALSE(is_class, ScopedEnumWithType);
    TEST_IS_TRAIT_CV_FALSE(is_class, EmptyUnion);
    TEST_IS_TRAIT_CV_FALSE(is_class, DummyUnion);
    TEST_IS_TRAIT_CV_FALSE(is_class, T);

    TEST_IS_TRAIT_CV(is_compound, EmptyClass);
    TEST_IS_TRAIT_CV(is_compound, DummyClass);
    TEST_IS_TRAIT_CV(is_compound, Abstract);
    TEST_IS_TRAIT_CV(is_compound, EmptyUnion);
    TEST_IS_TRAIT_CV(is_compound, DummyUnion);
    TEST_IS_TRAIT_CV(is_compound, Enum);
    TEST_IS_TRAIT_CV(is_compound, EnumWithType);
    TEST_IS_TRAIT_CV(is_compound, ScopedEnum);
    TEST_IS_TRAIT_CV(is_compound, ScopedEnumWithType);
    TEST_IS_TRAIT_CV(is_compound, T*);
    TEST_IS_TRAIT_CV(is_compound, T&);
    TEST_IS_TRAIT_CV_FALSE(is_compound, T);

    TEST_IS_TRAIT_CV(is_trivially_destructible, T);
    TEST_IS_TRAIT_CV(is_trivially_destructible, TrivialDtor);
    TEST_IS_TRAIT_CV(is_trivially_destructible, TrivialDtorDefaulted);
    TEST_IS_TRAIT_CV_FALSE(is_trivially_destructible, NonTrivialDtor);
    TEST_IS_TRAIT_CV_FALSE(is_trivially_destructible, NonTrivialDtorMember);

    // clang-format off
    TEST_IS_TRAIT(is_default_constructible, T);
    TEST_IS_TRAIT(is_default_constructible, T*);
    TEST_IS_TRAIT(is_default_constructible, TriviallyConstructable);
    TEST_IS_TRAIT_FALSE(is_default_constructible, NonTriviallyConstructable);

    TEST_IS_TRAIT(is_nothrow_default_constructible, T);
    TEST_IS_TRAIT(is_nothrow_default_constructible, T*);
    TEST_IS_TRAIT(is_nothrow_default_constructible, TriviallyConstructable);
    TEST_IS_TRAIT_FALSE(is_nothrow_default_constructible, NonTriviallyConstructable);

    TEST_IS_TRAIT(is_trivially_default_constructible, T);
    TEST_IS_TRAIT(is_trivially_default_constructible, T*);
    TEST_IS_TRAIT(is_trivially_default_constructible, TriviallyConstructable);
    TEST_IS_TRAIT_FALSE(is_trivially_default_constructible, NonTriviallyConstructable);
    // clang-format on

    CHECK(etl::is_trivially_constructible_v<T>);
    CHECK(etl::is_trivially_constructible_v<T*>);
    CHECK(etl::is_trivially_constructible_v<T, T&>);
    CHECK(etl::is_trivially_constructible_v<T, T const&>);

    CHECK_FALSE(etl::is_trivially_constructible_v<T&>);
    CHECK_FALSE(etl::is_trivially_constructible_v<T const&>);

    class Foo {
        T v1;      // NOLINT
        double v2; // NOLINT

    public:
        Foo(T n) : v1(n), v2() { }

        Foo(T n, double f) noexcept : v1(n), v2(f) { }
    };

    CHECK_FALSE(etl::is_trivially_constructible_v<Foo, T, double>);
    CHECK_FALSE(etl::is_trivially_constructible_v<Foo, T>);

    CHECK(etl::is_nothrow_constructible_v<T>);
    CHECK(etl::is_nothrow_constructible_v<T*>);
    CHECK(etl::is_nothrow_constructible_v<T, T&>);
    CHECK(etl::is_nothrow_constructible_v<T, T const&>);

    CHECK_FALSE(etl::is_nothrow_constructible_v<T&>);
    CHECK_FALSE(etl::is_nothrow_constructible_v<T const&>);

    CHECK(etl::is_nothrow_constructible_v<Foo, T, double>);
    CHECK_FALSE(etl::is_nothrow_constructible_v<Foo, T>);

    TEST_IS_TRAIT_CV(is_signed, signed char);
    TEST_IS_TRAIT_CV(is_signed, signed short);
    TEST_IS_TRAIT_CV(is_signed, signed int);
    TEST_IS_TRAIT_CV(is_signed, signed long);
    TEST_IS_TRAIT_CV(is_signed, signed long long);
    TEST_IS_TRAIT_CV(is_signed, short);
    TEST_IS_TRAIT_CV(is_signed, int);
    TEST_IS_TRAIT_CV(is_signed, long);
    TEST_IS_TRAIT_CV(is_signed, long long);
    TEST_IS_TRAIT_CV(is_signed, signed);
    TEST_IS_TRAIT_CV(is_signed, etl::int8_t);
    TEST_IS_TRAIT_CV(is_signed, etl::int16_t);
    TEST_IS_TRAIT_CV(is_signed, etl::int32_t);
    TEST_IS_TRAIT_CV(is_signed, etl::int64_t);

    TEST_IS_TRAIT_CV_FALSE(is_signed, unsigned char);
    TEST_IS_TRAIT_CV_FALSE(is_signed, unsigned short);
    TEST_IS_TRAIT_CV_FALSE(is_signed, unsigned int);
    TEST_IS_TRAIT_CV_FALSE(is_signed, unsigned long);
    TEST_IS_TRAIT_CV_FALSE(is_signed, unsigned long long);
    TEST_IS_TRAIT_CV_FALSE(is_signed, etl::uint8_t);
    TEST_IS_TRAIT_CV_FALSE(is_signed, etl::uint16_t);
    TEST_IS_TRAIT_CV_FALSE(is_signed, etl::uint32_t);
    TEST_IS_TRAIT_CV_FALSE(is_signed, etl::uint64_t);

    TEST_IS_TRAIT_CV(is_unsigned, unsigned char);
    TEST_IS_TRAIT_CV(is_unsigned, unsigned short);
    TEST_IS_TRAIT_CV(is_unsigned, unsigned int);
    TEST_IS_TRAIT_CV(is_unsigned, unsigned long);
    TEST_IS_TRAIT_CV(is_unsigned, unsigned long long);
    TEST_IS_TRAIT_CV(is_unsigned, etl::uint8_t);
    TEST_IS_TRAIT_CV(is_unsigned, etl::uint16_t);
    TEST_IS_TRAIT_CV(is_unsigned, etl::uint32_t);
    TEST_IS_TRAIT_CV(is_unsigned, etl::uint64_t);

    TEST_IS_TRAIT_CV_FALSE(is_unsigned, signed char);
    TEST_IS_TRAIT_CV_FALSE(is_unsigned, signed short);
    TEST_IS_TRAIT_CV_FALSE(is_unsigned, signed int);
    TEST_IS_TRAIT_CV_FALSE(is_unsigned, signed long);
    TEST_IS_TRAIT_CV_FALSE(is_unsigned, signed long long);
    TEST_IS_TRAIT_CV_FALSE(is_unsigned, short);
    TEST_IS_TRAIT_CV_FALSE(is_unsigned, int);
    TEST_IS_TRAIT_CV_FALSE(is_unsigned, long);
    TEST_IS_TRAIT_CV_FALSE(is_unsigned, long long);
    TEST_IS_TRAIT_CV_FALSE(is_unsigned, signed);
    TEST_IS_TRAIT_CV_FALSE(is_unsigned, etl::int8_t);
    TEST_IS_TRAIT_CV_FALSE(is_unsigned, etl::int16_t);
    TEST_IS_TRAIT_CV_FALSE(is_unsigned, etl::int32_t);
    TEST_IS_TRAIT_CV_FALSE(is_unsigned, etl::int64_t);

    TEST_IS_TRAIT_CV(is_standard_unsigned_integer, unsigned char);
    TEST_IS_TRAIT_CV(is_standard_unsigned_integer, unsigned short);
    TEST_IS_TRAIT_CV(is_standard_unsigned_integer, unsigned int);
    TEST_IS_TRAIT_CV(is_standard_unsigned_integer, unsigned long);
    TEST_IS_TRAIT_CV(is_standard_unsigned_integer, unsigned long long);
    TEST_IS_TRAIT_CV(is_standard_unsigned_integer, etl::uint8_t);
    TEST_IS_TRAIT_CV(is_standard_unsigned_integer, etl::uint16_t);
    TEST_IS_TRAIT_CV(is_standard_unsigned_integer, etl::uint32_t);
    TEST_IS_TRAIT_CV(is_standard_unsigned_integer, etl::uint64_t);

    TEST_IS_TRAIT_CV(is_standard_signed_integer, signed char);
    TEST_IS_TRAIT_CV(is_standard_signed_integer, signed short);
    TEST_IS_TRAIT_CV(is_standard_signed_integer, signed int);
    TEST_IS_TRAIT_CV(is_standard_signed_integer, signed long);
    TEST_IS_TRAIT_CV(is_standard_signed_integer, signed long long);
    TEST_IS_TRAIT_CV(is_standard_signed_integer, etl::int8_t);
    TEST_IS_TRAIT_CV(is_standard_signed_integer, etl::int16_t);
    TEST_IS_TRAIT_CV(is_standard_signed_integer, etl::int32_t);
    TEST_IS_TRAIT_CV(is_standard_signed_integer, etl::int64_t);

    TEST_IS_TRAIT_CV(is_standard_integer, unsigned char);
    TEST_IS_TRAIT_CV(is_standard_integer, unsigned short);
    TEST_IS_TRAIT_CV(is_standard_integer, unsigned int);
    TEST_IS_TRAIT_CV(is_standard_integer, unsigned long);
    TEST_IS_TRAIT_CV(is_standard_integer, unsigned long long);
    TEST_IS_TRAIT_CV(is_standard_integer, signed char);
    TEST_IS_TRAIT_CV(is_standard_integer, signed short);
    TEST_IS_TRAIT_CV(is_standard_integer, signed int);
    TEST_IS_TRAIT_CV(is_standard_integer, signed long);
    TEST_IS_TRAIT_CV(is_standard_integer, signed long long);
    TEST_IS_TRAIT_CV(is_standard_integer, etl::uint8_t);
    TEST_IS_TRAIT_CV(is_standard_integer, etl::uint16_t);
    TEST_IS_TRAIT_CV(is_standard_integer, etl::uint32_t);
    TEST_IS_TRAIT_CV(is_standard_integer, etl::uint64_t);
    TEST_IS_TRAIT_CV(is_standard_integer, etl::int8_t);
    TEST_IS_TRAIT_CV(is_standard_integer, etl::int16_t);
    TEST_IS_TRAIT_CV(is_standard_integer, etl::int32_t);
    TEST_IS_TRAIT_CV(is_standard_integer, etl::int64_t);

    struct AlignmenTest {
        float f; // NOLINT
    };

    TEST_TRAIT_VALUE_CV(alignment_of, char, 1);
    TEST_TRAIT_VALUE_CV(alignment_of, signed char, 1);
    TEST_TRAIT_VALUE_CV(alignment_of, unsigned char, 1);

    TEST_TRAIT_VALUE_CV(alignment_of, short, 2);
    TEST_TRAIT_VALUE_CV(alignment_of, signed short, 2);
    TEST_TRAIT_VALUE_CV(alignment_of, unsigned short, 2);

    TEST_TRAIT_VALUE_CV(alignment_of, int, 4);
    TEST_TRAIT_VALUE_CV(alignment_of, signed int, 4);
    TEST_TRAIT_VALUE_CV(alignment_of, unsigned int, 4);

    if constexpr (sizeof(long) == 4U) {
        TEST_TRAIT_VALUE_CV(alignment_of, long, 4);
        TEST_TRAIT_VALUE_CV(alignment_of, signed long, 4);
        TEST_TRAIT_VALUE_CV(alignment_of, unsigned long, 4);
    } else {
        TEST_TRAIT_VALUE_CV(alignment_of, long, 8);
        TEST_TRAIT_VALUE_CV(alignment_of, signed long, 8);
        TEST_TRAIT_VALUE_CV(alignment_of, unsigned long, 8);
    }

    TEST_TRAIT_VALUE_CV(alignment_of, long long, 8);
    TEST_TRAIT_VALUE_CV(alignment_of, signed long long, 8);
    TEST_TRAIT_VALUE_CV(alignment_of, unsigned long long, 8);

    TEST_TRAIT_VALUE_CV(alignment_of, float, 4);
    TEST_TRAIT_VALUE_CV(alignment_of, double, 8);

    TEST_TRAIT_VALUE_CV(alignment_of, AlignmenTest, 4);

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test<char>());
    CHECK(test<etl::uint8_t>());
    CHECK(test<etl::uint16_t>());
    CHECK(test<etl::uint32_t>());
    CHECK(test<etl::uint64_t>());
    CHECK(test<etl::int8_t>());
    CHECK(test<etl::int16_t>());
    CHECK(test<etl::int32_t>());
    CHECK(test<etl::int64_t>());

    CHECK(test<float>());
    CHECK(test<double>());
    CHECK(test<long double>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
#else
auto main() -> int { return 0; }
#endif
