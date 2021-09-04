/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/type_traits.hpp"

#include "etl/version.hpp"

#include "testing.hpp"
#include "types.hpp"

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

    TEST_IS_TRAIT_CV(is_union, EmptyUnion);
    TEST_IS_TRAIT_CV(is_union, DummyUnion);

    TEST_IS_TRAIT_CV_FALSE(is_union, Enum);
    TEST_IS_TRAIT_CV_FALSE(is_union, EnumWithType);
    TEST_IS_TRAIT_CV_FALSE(is_union, ScopedEnum);
    TEST_IS_TRAIT_CV_FALSE(is_union, ScopedEnumWithType);
    TEST_IS_TRAIT_CV_FALSE(is_union, EmptyClass);
    TEST_IS_TRAIT_CV_FALSE(is_union, DummyClass);
    TEST_IS_TRAIT_CV_FALSE(is_union, Abstract);

    TEST_IS_TRAIT_CV(is_class, EmptyClass);
    TEST_IS_TRAIT_CV(is_class, DummyClass);
    TEST_IS_TRAIT_CV(is_class, Abstract);

    TEST_IS_TRAIT_CV_FALSE(is_class, Enum);
    TEST_IS_TRAIT_CV_FALSE(is_class, EnumWithType);
    TEST_IS_TRAIT_CV_FALSE(is_class, ScopedEnum);
    TEST_IS_TRAIT_CV_FALSE(is_class, ScopedEnumWithType);
    TEST_IS_TRAIT_CV_FALSE(is_class, EmptyUnion);
    TEST_IS_TRAIT_CV_FALSE(is_class, DummyUnion);

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

    return true;
}

constexpr auto test_all() -> bool
{
    assert(test<etl::uint8_t>());
    assert(test<etl::int8_t>());
    assert(test<etl::uint16_t>());
    assert(test<etl::int16_t>());
    assert(test<etl::uint32_t>());
    assert(test<etl::int32_t>());
    assert(test<etl::uint64_t>());
    assert(test<etl::int64_t>());

    assert(test<float>());
    assert(test<double>());
    assert(test<long double>());

    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}