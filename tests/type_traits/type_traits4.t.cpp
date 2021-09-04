/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/type_traits.hpp"

#include "etl/version.hpp"

#include "testing.hpp"
#include "types.hpp"

#define TEST_IS_TRAIT(trait, type)                                             \
    do {                                                                       \
        assert(etl::is_base_of_v<etl::true_type, etl::trait<type>>);           \
        assert((etl::trait<type>::value));                                     \
        assert((etl::TETL_PP_CONCAT(trait, _v) < type >));                     \
    } while (false)

#define TEST_IS_TRAIT_FALSE(trait, type)                                       \
    do {                                                                       \
        assert((etl::is_base_of_v<etl::false_type, etl::trait<type>>));        \
        assert(!(etl::trait<type>::value));                                    \
        assert(!(etl::TETL_PP_CONCAT(trait, _v) < type >));                    \
    } while (false)

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

    TEST_IS_TRAIT_FALSE(is_member_pointer, T);
    TEST_IS_TRAIT_FALSE(is_member_pointer, T const);
    TEST_IS_TRAIT_FALSE(is_member_pointer, T volatile);
    TEST_IS_TRAIT_FALSE(is_member_pointer, T const volatile);

    TEST_IS_TRAIT_FALSE(is_member_pointer, T*);
    TEST_IS_TRAIT_FALSE(is_member_pointer, T const*);
    TEST_IS_TRAIT_FALSE(is_member_pointer, T volatile*);
    TEST_IS_TRAIT_FALSE(is_member_pointer, T const volatile*);

    TEST_IS_TRAIT(is_member_function_pointer, PointerToMemberFunc);
    TEST_IS_TRAIT(is_member_function_pointer, PointerToConstMemberFunc);
    TEST_IS_TRAIT(is_member_function_pointer, PointerToVolatileMemberFunc);
    TEST_IS_TRAIT(is_member_function_pointer, PointerToCVMemberFunc);

    TEST_IS_TRAIT_FALSE(is_member_function_pointer, PointerToMemberObj);
    TEST_IS_TRAIT_FALSE(is_member_function_pointer, PointerToConstMemberObj);
    TEST_IS_TRAIT_FALSE(is_member_function_pointer, PointerToVolatileMemberObj);
    TEST_IS_TRAIT_FALSE(is_member_function_pointer, PointerToCVMemberObj);

    TEST_IS_TRAIT_FALSE(is_member_function_pointer, T);
    TEST_IS_TRAIT_FALSE(is_member_function_pointer, T const);
    TEST_IS_TRAIT_FALSE(is_member_function_pointer, T volatile);
    TEST_IS_TRAIT_FALSE(is_member_function_pointer, T const volatile);

    TEST_IS_TRAIT_FALSE(is_member_function_pointer, T*);
    TEST_IS_TRAIT_FALSE(is_member_function_pointer, T const*);
    TEST_IS_TRAIT_FALSE(is_member_function_pointer, T volatile*);
    TEST_IS_TRAIT_FALSE(is_member_function_pointer, T const volatile*);

    using etl::is_member_object_pointer_v;

    TEST_IS_TRAIT(is_member_object_pointer, PointerToMemberObj);
    TEST_IS_TRAIT(is_member_object_pointer, PointerToConstMemberObj);
    TEST_IS_TRAIT(is_member_object_pointer, PointerToVolatileMemberObj);
    TEST_IS_TRAIT(is_member_object_pointer, PointerToCVMemberObj);

    TEST_IS_TRAIT_FALSE(is_member_object_pointer, PointerToMemberFunc);
    TEST_IS_TRAIT_FALSE(is_member_object_pointer, PointerToConstMemberFunc);
    TEST_IS_TRAIT_FALSE(is_member_object_pointer, PointerToVolatileMemberFunc);
    TEST_IS_TRAIT_FALSE(is_member_object_pointer, PointerToCVMemberFunc);

    TEST_IS_TRAIT_FALSE(is_member_object_pointer, T);
    TEST_IS_TRAIT_FALSE(is_member_object_pointer, T const);
    TEST_IS_TRAIT_FALSE(is_member_object_pointer, T volatile);
    TEST_IS_TRAIT_FALSE(is_member_object_pointer, T const volatile);

    TEST_IS_TRAIT_FALSE(is_member_object_pointer, T*);
    TEST_IS_TRAIT_FALSE(is_member_object_pointer, T const*);
    TEST_IS_TRAIT_FALSE(is_member_object_pointer, T volatile*);
    TEST_IS_TRAIT_FALSE(is_member_object_pointer, T const volatile*);

    TEST_IS_TRAIT(is_enum, Enum);
    TEST_IS_TRAIT(is_enum, Enum const);
    TEST_IS_TRAIT(is_enum, Enum volatile);
    TEST_IS_TRAIT(is_enum, EnumWithType);
    TEST_IS_TRAIT(is_enum, EnumWithType const);
    TEST_IS_TRAIT(is_enum, EnumWithType volatile);
    TEST_IS_TRAIT(is_enum, ScopedEnum);
    TEST_IS_TRAIT(is_enum, ScopedEnum const);
    TEST_IS_TRAIT(is_enum, ScopedEnum volatile);
    TEST_IS_TRAIT(is_enum, ScopedEnumWithType);
    TEST_IS_TRAIT(is_enum, ScopedEnumWithType const);
    TEST_IS_TRAIT(is_enum, ScopedEnumWithType volatile);

    TEST_IS_TRAIT_FALSE(is_enum, EmptyClass);
    TEST_IS_TRAIT_FALSE(is_enum, EmptyClass const);
    TEST_IS_TRAIT_FALSE(is_enum, EmptyClass volatile);
    TEST_IS_TRAIT_FALSE(is_enum, EmptyUnion);
    TEST_IS_TRAIT_FALSE(is_enum, EmptyUnion const);
    TEST_IS_TRAIT_FALSE(is_enum, EmptyUnion volatile);
    TEST_IS_TRAIT_FALSE(is_enum, Abstract);
    TEST_IS_TRAIT_FALSE(is_enum, Abstract const);
    TEST_IS_TRAIT_FALSE(is_enum, Abstract volatile);

    TEST_IS_TRAIT(is_union, EmptyUnion);
    TEST_IS_TRAIT(is_union, EmptyUnion const);
    TEST_IS_TRAIT(is_union, EmptyUnion volatile);
    TEST_IS_TRAIT(is_union, DummyUnion);
    TEST_IS_TRAIT(is_union, DummyUnion const);
    TEST_IS_TRAIT(is_union, DummyUnion volatile);

    TEST_IS_TRAIT_FALSE(is_union, Enum);
    TEST_IS_TRAIT_FALSE(is_union, Enum const);
    TEST_IS_TRAIT_FALSE(is_union, Enum volatile);
    TEST_IS_TRAIT_FALSE(is_union, EnumWithType);
    TEST_IS_TRAIT_FALSE(is_union, EnumWithType const);
    TEST_IS_TRAIT_FALSE(is_union, EnumWithType volatile);
    TEST_IS_TRAIT_FALSE(is_union, ScopedEnum);
    TEST_IS_TRAIT_FALSE(is_union, ScopedEnum const);
    TEST_IS_TRAIT_FALSE(is_union, ScopedEnum volatile);
    TEST_IS_TRAIT_FALSE(is_union, ScopedEnumWithType);
    TEST_IS_TRAIT_FALSE(is_union, ScopedEnumWithType const);
    TEST_IS_TRAIT_FALSE(is_union, ScopedEnumWithType volatile);
    TEST_IS_TRAIT_FALSE(is_union, EmptyClass);
    TEST_IS_TRAIT_FALSE(is_union, EmptyClass const);
    TEST_IS_TRAIT_FALSE(is_union, EmptyClass volatile);
    TEST_IS_TRAIT_FALSE(is_union, DummyClass);
    TEST_IS_TRAIT_FALSE(is_union, DummyClass const);
    TEST_IS_TRAIT_FALSE(is_union, DummyClass volatile);
    TEST_IS_TRAIT_FALSE(is_union, Abstract);
    TEST_IS_TRAIT_FALSE(is_union, Abstract const);
    TEST_IS_TRAIT_FALSE(is_union, Abstract volatile);

    TEST_IS_TRAIT(is_class, EmptyClass);
    TEST_IS_TRAIT(is_class, EmptyClass const);
    TEST_IS_TRAIT(is_class, EmptyClass volatile);
    TEST_IS_TRAIT(is_class, DummyClass);
    TEST_IS_TRAIT(is_class, DummyClass const);
    TEST_IS_TRAIT(is_class, DummyClass volatile);
    TEST_IS_TRAIT(is_class, Abstract);
    TEST_IS_TRAIT(is_class, Abstract const);
    TEST_IS_TRAIT(is_class, Abstract volatile);

    TEST_IS_TRAIT_FALSE(is_class, Enum);
    TEST_IS_TRAIT_FALSE(is_class, Enum const);
    TEST_IS_TRAIT_FALSE(is_class, Enum volatile);
    TEST_IS_TRAIT_FALSE(is_class, EnumWithType);
    TEST_IS_TRAIT_FALSE(is_class, EnumWithType const);
    TEST_IS_TRAIT_FALSE(is_class, EnumWithType volatile);
    TEST_IS_TRAIT_FALSE(is_class, ScopedEnum);
    TEST_IS_TRAIT_FALSE(is_class, ScopedEnum const);
    TEST_IS_TRAIT_FALSE(is_class, ScopedEnum volatile);
    TEST_IS_TRAIT_FALSE(is_class, ScopedEnumWithType);
    TEST_IS_TRAIT_FALSE(is_class, ScopedEnumWithType const);
    TEST_IS_TRAIT_FALSE(is_class, ScopedEnumWithType volatile);
    TEST_IS_TRAIT_FALSE(is_class, EmptyUnion);
    TEST_IS_TRAIT_FALSE(is_class, EmptyUnion const);
    TEST_IS_TRAIT_FALSE(is_class, EmptyUnion volatile);
    TEST_IS_TRAIT_FALSE(is_class, DummyUnion);
    TEST_IS_TRAIT_FALSE(is_class, DummyUnion const);
    TEST_IS_TRAIT_FALSE(is_class, DummyUnion volatile);

    TEST_IS_TRAIT(is_compound, EmptyClass);
    TEST_IS_TRAIT(is_compound, EmptyClass const);
    TEST_IS_TRAIT(is_compound, EmptyClass volatile);
    TEST_IS_TRAIT(is_compound, DummyClass);
    TEST_IS_TRAIT(is_compound, DummyClass const);
    TEST_IS_TRAIT(is_compound, DummyClass volatile);
    TEST_IS_TRAIT(is_compound, Abstract);
    TEST_IS_TRAIT(is_compound, Abstract const);
    TEST_IS_TRAIT(is_compound, Abstract volatile);
    TEST_IS_TRAIT(is_compound, EmptyUnion);
    TEST_IS_TRAIT(is_compound, EmptyUnion const);
    TEST_IS_TRAIT(is_compound, EmptyUnion volatile);
    TEST_IS_TRAIT(is_compound, DummyUnion);
    TEST_IS_TRAIT(is_compound, DummyUnion const);
    TEST_IS_TRAIT(is_compound, DummyUnion volatile);
    TEST_IS_TRAIT(is_compound, Enum);
    TEST_IS_TRAIT(is_compound, Enum const);
    TEST_IS_TRAIT(is_compound, Enum volatile);
    TEST_IS_TRAIT(is_compound, EnumWithType);
    TEST_IS_TRAIT(is_compound, EnumWithType const);
    TEST_IS_TRAIT(is_compound, EnumWithType volatile);
    TEST_IS_TRAIT(is_compound, ScopedEnum);
    TEST_IS_TRAIT(is_compound, ScopedEnum const);
    TEST_IS_TRAIT(is_compound, ScopedEnum volatile);
    TEST_IS_TRAIT(is_compound, ScopedEnumWithType);
    TEST_IS_TRAIT(is_compound, ScopedEnumWithType const);
    TEST_IS_TRAIT(is_compound, ScopedEnumWithType volatile);

    TEST_IS_TRAIT_FALSE(is_compound, T);
    TEST_IS_TRAIT_FALSE(is_compound, T const);
    TEST_IS_TRAIT_FALSE(is_compound, T volatile);
    TEST_IS_TRAIT_FALSE(is_compound, T const volatile);

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