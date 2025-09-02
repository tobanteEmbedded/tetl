// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"
#include "testing/types.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/cstddef.hpp>
    #include <etl/cstdint.hpp>
    #include <etl/type_traits.hpp>
#endif

template <typename T>
static constexpr auto test() -> bool
{
    CHECK_IS_TRAIT(is_member_pointer, PointerToMemberFunc);
    CHECK_IS_TRAIT(is_member_pointer, PointerToConstMemberFunc);
    CHECK_IS_TRAIT(is_member_pointer, PointerToVolatileMemberFunc);
    CHECK_IS_TRAIT(is_member_pointer, PointerToCVMemberFunc);
    CHECK_IS_TRAIT(is_member_pointer, PointerToMemberObj);
    CHECK_IS_TRAIT(is_member_pointer, PointerToConstMemberObj);
    CHECK_IS_TRAIT(is_member_pointer, PointerToVolatileMemberObj);
    CHECK_IS_TRAIT(is_member_pointer, PointerToCVMemberObj);
    CHECK_IS_TRAIT_CV_FALSE(is_member_pointer, T);
    CHECK_IS_TRAIT_CV_FALSE(is_member_pointer, T*);

    CHECK_IS_TRAIT(is_member_function_pointer, PointerToMemberFunc);
    CHECK_IS_TRAIT(is_member_function_pointer, PointerToConstMemberFunc);
    CHECK_IS_TRAIT(is_member_function_pointer, PointerToVolatileMemberFunc);
    CHECK_IS_TRAIT(is_member_function_pointer, PointerToCVMemberFunc);
    CHECK_IS_TRAIT_FALSE(is_member_function_pointer, PointerToMemberObj);
    CHECK_IS_TRAIT_FALSE(is_member_function_pointer, PointerToConstMemberObj);
    CHECK_IS_TRAIT_FALSE(is_member_function_pointer, PointerToVolatileMemberObj);
    CHECK_IS_TRAIT_FALSE(is_member_function_pointer, PointerToCVMemberObj);
    CHECK_IS_TRAIT_CV_FALSE(is_member_function_pointer, T);
    CHECK_IS_TRAIT_CV_FALSE(is_member_function_pointer, T*);

    CHECK_IS_TRAIT(is_member_object_pointer, PointerToMemberObj);
    CHECK_IS_TRAIT(is_member_object_pointer, PointerToConstMemberObj);
    CHECK_IS_TRAIT(is_member_object_pointer, PointerToVolatileMemberObj);
    CHECK_IS_TRAIT(is_member_object_pointer, PointerToCVMemberObj);
    CHECK_IS_TRAIT_FALSE(is_member_object_pointer, PointerToMemberFunc);
    CHECK_IS_TRAIT_FALSE(is_member_object_pointer, PointerToConstMemberFunc);
    CHECK_IS_TRAIT_FALSE(is_member_object_pointer, PointerToVolatileMemberFunc);
    CHECK_IS_TRAIT_FALSE(is_member_object_pointer, PointerToCVMemberFunc);
    CHECK_IS_TRAIT_CV_FALSE(is_member_object_pointer, T);
    CHECK_IS_TRAIT_CV_FALSE(is_member_object_pointer, T*);

    CHECK_IS_TRAIT_CV(is_enum, Enum);
    CHECK_IS_TRAIT_CV(is_enum, EnumWithType);
    CHECK_IS_TRAIT_CV(is_enum, ScopedEnum);
    CHECK_IS_TRAIT_CV(is_enum, ScopedEnumWithType);
    CHECK_IS_TRAIT_CV_FALSE(is_enum, EmptyClass);
    CHECK_IS_TRAIT_CV_FALSE(is_enum, EmptyUnion);
    CHECK_IS_TRAIT_CV_FALSE(is_enum, Abstract);
    CHECK_IS_TRAIT_CV_FALSE(is_enum, T);

    CHECK_IS_TRAIT_CV(is_union, EmptyUnion);
    CHECK_IS_TRAIT_CV(is_union, DummyUnion);
    CHECK_IS_TRAIT_CV_FALSE(is_union, Enum);
    CHECK_IS_TRAIT_CV_FALSE(is_union, EnumWithType);
    CHECK_IS_TRAIT_CV_FALSE(is_union, ScopedEnum);
    CHECK_IS_TRAIT_CV_FALSE(is_union, ScopedEnumWithType);
    CHECK_IS_TRAIT_CV_FALSE(is_union, EmptyClass);
    CHECK_IS_TRAIT_CV_FALSE(is_union, DummyClass);
    CHECK_IS_TRAIT_CV_FALSE(is_union, Abstract);
    CHECK_IS_TRAIT_CV_FALSE(is_union, T);

    CHECK_IS_TRAIT_CV(is_class, EmptyClass);
    CHECK_IS_TRAIT_CV(is_class, DummyClass);
    CHECK_IS_TRAIT_CV(is_class, Abstract);
    CHECK_IS_TRAIT_CV_FALSE(is_class, Enum);
    CHECK_IS_TRAIT_CV_FALSE(is_class, EnumWithType);
    CHECK_IS_TRAIT_CV_FALSE(is_class, ScopedEnum);
    CHECK_IS_TRAIT_CV_FALSE(is_class, ScopedEnumWithType);
    CHECK_IS_TRAIT_CV_FALSE(is_class, EmptyUnion);
    CHECK_IS_TRAIT_CV_FALSE(is_class, DummyUnion);
    CHECK_IS_TRAIT_CV_FALSE(is_class, T);

    CHECK_IS_TRAIT_CV(is_compound, EmptyClass);
    CHECK_IS_TRAIT_CV(is_compound, DummyClass);
    CHECK_IS_TRAIT_CV(is_compound, Abstract);
    CHECK_IS_TRAIT_CV(is_compound, EmptyUnion);
    CHECK_IS_TRAIT_CV(is_compound, DummyUnion);
    CHECK_IS_TRAIT_CV(is_compound, Enum);
    CHECK_IS_TRAIT_CV(is_compound, EnumWithType);
    CHECK_IS_TRAIT_CV(is_compound, ScopedEnum);
    CHECK_IS_TRAIT_CV(is_compound, ScopedEnumWithType);
    CHECK_IS_TRAIT_CV(is_compound, T*);
    CHECK_IS_TRAIT_CV(is_compound, T&);
    CHECK_IS_TRAIT_CV_FALSE(is_compound, T);

    CHECK_IS_TRAIT_CV(is_trivially_destructible, T);
    CHECK_IS_TRAIT_CV(is_trivially_destructible, TrivialDtor);
    CHECK_IS_TRAIT_CV(is_trivially_destructible, TrivialDtorDefaulted);
    CHECK_IS_TRAIT_CV_FALSE(is_trivially_destructible, NonTrivialDtor);
    CHECK_IS_TRAIT_CV_FALSE(is_trivially_destructible, NonTrivialDtorMember);

    CHECK_IS_TRAIT(is_default_constructible, T);
    CHECK_IS_TRAIT(is_default_constructible, T*);
    CHECK_IS_TRAIT(is_default_constructible, TriviallyConstructable);
    CHECK_IS_TRAIT_FALSE(is_default_constructible, NonTriviallyConstructable);

    CHECK_IS_TRAIT(is_nothrow_default_constructible, T);
    CHECK_IS_TRAIT(is_nothrow_default_constructible, T*);
    CHECK_IS_TRAIT(is_nothrow_default_constructible, TriviallyConstructable);
    CHECK_IS_TRAIT_FALSE(is_nothrow_default_constructible, NonTriviallyConstructable);

    CHECK_IS_TRAIT(is_trivially_default_constructible, T);
    CHECK_IS_TRAIT(is_trivially_default_constructible, T*);
    CHECK_IS_TRAIT(is_trivially_default_constructible, TriviallyConstructable);
    CHECK_IS_TRAIT_FALSE(is_trivially_default_constructible, NonTriviallyConstructable);

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
        Foo(T n)
            : v1(n)
            , v2()
        {
        }

        Foo(T n, double f) noexcept
            : v1(n)
            , v2(f)
        {
        }
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

    CHECK_IS_TRAIT_CV(is_signed, signed char);
    CHECK_IS_TRAIT_CV(is_signed, signed short);
    CHECK_IS_TRAIT_CV(is_signed, signed int);
    CHECK_IS_TRAIT_CV(is_signed, signed long);
    CHECK_IS_TRAIT_CV(is_signed, signed long long);
    CHECK_IS_TRAIT_CV(is_signed, short);
    CHECK_IS_TRAIT_CV(is_signed, int);
    CHECK_IS_TRAIT_CV(is_signed, long);
    CHECK_IS_TRAIT_CV(is_signed, long long);
    CHECK_IS_TRAIT_CV(is_signed, signed);
    CHECK_IS_TRAIT_CV(is_signed, etl::int8_t);
    CHECK_IS_TRAIT_CV(is_signed, etl::int16_t);
    CHECK_IS_TRAIT_CV(is_signed, etl::int32_t);
    CHECK_IS_TRAIT_CV(is_signed, etl::int64_t);

    CHECK_IS_TRAIT_CV_FALSE(is_signed, unsigned char);
    CHECK_IS_TRAIT_CV_FALSE(is_signed, unsigned short);
    CHECK_IS_TRAIT_CV_FALSE(is_signed, unsigned int);
    CHECK_IS_TRAIT_CV_FALSE(is_signed, unsigned long);
    CHECK_IS_TRAIT_CV_FALSE(is_signed, unsigned long long);
    CHECK_IS_TRAIT_CV_FALSE(is_signed, etl::uint8_t);
    CHECK_IS_TRAIT_CV_FALSE(is_signed, etl::uint16_t);
    CHECK_IS_TRAIT_CV_FALSE(is_signed, etl::uint32_t);
    CHECK_IS_TRAIT_CV_FALSE(is_signed, etl::uint64_t);

    CHECK_IS_TRAIT_CV(is_unsigned, unsigned char);
    CHECK_IS_TRAIT_CV(is_unsigned, unsigned short);
    CHECK_IS_TRAIT_CV(is_unsigned, unsigned int);
    CHECK_IS_TRAIT_CV(is_unsigned, unsigned long);
    CHECK_IS_TRAIT_CV(is_unsigned, unsigned long long);
    CHECK_IS_TRAIT_CV(is_unsigned, etl::uint8_t);
    CHECK_IS_TRAIT_CV(is_unsigned, etl::uint16_t);
    CHECK_IS_TRAIT_CV(is_unsigned, etl::uint32_t);
    CHECK_IS_TRAIT_CV(is_unsigned, etl::uint64_t);

    CHECK_IS_TRAIT_CV_FALSE(is_unsigned, signed char);
    CHECK_IS_TRAIT_CV_FALSE(is_unsigned, signed short);
    CHECK_IS_TRAIT_CV_FALSE(is_unsigned, signed int);
    CHECK_IS_TRAIT_CV_FALSE(is_unsigned, signed long);
    CHECK_IS_TRAIT_CV_FALSE(is_unsigned, signed long long);
    CHECK_IS_TRAIT_CV_FALSE(is_unsigned, short);
    CHECK_IS_TRAIT_CV_FALSE(is_unsigned, int);
    CHECK_IS_TRAIT_CV_FALSE(is_unsigned, long);
    CHECK_IS_TRAIT_CV_FALSE(is_unsigned, long long);
    CHECK_IS_TRAIT_CV_FALSE(is_unsigned, signed);
    CHECK_IS_TRAIT_CV_FALSE(is_unsigned, etl::int8_t);
    CHECK_IS_TRAIT_CV_FALSE(is_unsigned, etl::int16_t);
    CHECK_IS_TRAIT_CV_FALSE(is_unsigned, etl::int32_t);
    CHECK_IS_TRAIT_CV_FALSE(is_unsigned, etl::int64_t);

    CHECK_IS_TRAIT_CV(is_builtin_unsigned_integer, unsigned char);
    CHECK_IS_TRAIT_CV(is_builtin_unsigned_integer, unsigned short);
    CHECK_IS_TRAIT_CV(is_builtin_unsigned_integer, unsigned int);
    CHECK_IS_TRAIT_CV(is_builtin_unsigned_integer, unsigned long);
    CHECK_IS_TRAIT_CV(is_builtin_unsigned_integer, unsigned long long);
    CHECK_IS_TRAIT_CV(is_builtin_unsigned_integer, etl::uint8_t);
    CHECK_IS_TRAIT_CV(is_builtin_unsigned_integer, etl::uint16_t);
    CHECK_IS_TRAIT_CV(is_builtin_unsigned_integer, etl::uint32_t);
    CHECK_IS_TRAIT_CV(is_builtin_unsigned_integer, etl::uint64_t);

    CHECK_IS_TRAIT_CV(is_builtin_signed_integer, signed char);
    CHECK_IS_TRAIT_CV(is_builtin_signed_integer, signed short);
    CHECK_IS_TRAIT_CV(is_builtin_signed_integer, signed int);
    CHECK_IS_TRAIT_CV(is_builtin_signed_integer, signed long);
    CHECK_IS_TRAIT_CV(is_builtin_signed_integer, signed long long);
    CHECK_IS_TRAIT_CV(is_builtin_signed_integer, etl::int8_t);
    CHECK_IS_TRAIT_CV(is_builtin_signed_integer, etl::int16_t);
    CHECK_IS_TRAIT_CV(is_builtin_signed_integer, etl::int32_t);
    CHECK_IS_TRAIT_CV(is_builtin_signed_integer, etl::int64_t);

    CHECK_IS_TRAIT_CV(is_builtin_integer, unsigned char);
    CHECK_IS_TRAIT_CV(is_builtin_integer, unsigned short);
    CHECK_IS_TRAIT_CV(is_builtin_integer, unsigned int);
    CHECK_IS_TRAIT_CV(is_builtin_integer, unsigned long);
    CHECK_IS_TRAIT_CV(is_builtin_integer, unsigned long long);
    CHECK_IS_TRAIT_CV(is_builtin_integer, signed char);
    CHECK_IS_TRAIT_CV(is_builtin_integer, signed short);
    CHECK_IS_TRAIT_CV(is_builtin_integer, signed int);
    CHECK_IS_TRAIT_CV(is_builtin_integer, signed long);
    CHECK_IS_TRAIT_CV(is_builtin_integer, signed long long);
    CHECK_IS_TRAIT_CV(is_builtin_integer, etl::uint8_t);
    CHECK_IS_TRAIT_CV(is_builtin_integer, etl::uint16_t);
    CHECK_IS_TRAIT_CV(is_builtin_integer, etl::uint32_t);
    CHECK_IS_TRAIT_CV(is_builtin_integer, etl::uint64_t);
    CHECK_IS_TRAIT_CV(is_builtin_integer, etl::int8_t);
    CHECK_IS_TRAIT_CV(is_builtin_integer, etl::int16_t);
    CHECK_IS_TRAIT_CV(is_builtin_integer, etl::int32_t);
    CHECK_IS_TRAIT_CV(is_builtin_integer, etl::int64_t);

    struct AlignmenTest {
        float f; // NOLINT
    };

    CHECK_TRAIT_VALUE_CV(alignment_of, char, alignof(char));
    CHECK_TRAIT_VALUE_CV(alignment_of, signed char, alignof(signed char));
    CHECK_TRAIT_VALUE_CV(alignment_of, unsigned char, alignof(unsigned char));

    CHECK_TRAIT_VALUE_CV(alignment_of, short, alignof(short));
    CHECK_TRAIT_VALUE_CV(alignment_of, signed short, alignof(signed short));
    CHECK_TRAIT_VALUE_CV(alignment_of, unsigned short, alignof(unsigned short));

    CHECK_TRAIT_VALUE_CV(alignment_of, int, alignof(int));
    CHECK_TRAIT_VALUE_CV(alignment_of, signed int, alignof(signed int));
    CHECK_TRAIT_VALUE_CV(alignment_of, unsigned int, alignof(unsigned int));

    if constexpr (sizeof(long) == 4U) {
        CHECK_TRAIT_VALUE_CV(alignment_of, long, alignof(long));
        CHECK_TRAIT_VALUE_CV(alignment_of, signed long, alignof(signed long));
        CHECK_TRAIT_VALUE_CV(alignment_of, unsigned long, alignof(unsigned long));
    } else {
        CHECK_TRAIT_VALUE_CV(alignment_of, long, alignof(long));
        CHECK_TRAIT_VALUE_CV(alignment_of, signed long, alignof(signed long));
        CHECK_TRAIT_VALUE_CV(alignment_of, unsigned long, alignof(unsigned long));
    }

    CHECK_TRAIT_VALUE_CV(alignment_of, long long, alignof(long long));
    CHECK_TRAIT_VALUE_CV(alignment_of, signed long long, alignof(signed long long));
    CHECK_TRAIT_VALUE_CV(alignment_of, unsigned long long, alignof(unsigned long long));

    CHECK_TRAIT_VALUE_CV(alignment_of, float, alignof(float));
    CHECK_TRAIT_VALUE_CV(alignment_of, double, alignof(double));

    CHECK_TRAIT_VALUE_CV(alignment_of, AlignmenTest, alignof(AlignmenTest));

    return true;
}

static constexpr auto test_all() -> bool
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
