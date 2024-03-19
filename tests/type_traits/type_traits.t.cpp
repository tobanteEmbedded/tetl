// SPDX-License-Identifier: BSL-1.0

#include <etl/type_traits.hpp>

#include <etl/cstdint.hpp>
#include <etl/version.hpp>

#include "testing/testing.hpp"
#include "testing/types.hpp"

#if not defined(TETL_WORKAROUND_AVR_BROKEN_TESTS)

namespace {
template <typename T>
struct Foo {
    T i{};
};

struct IDS { };
template <typename T>
struct test_is_specialized;

template <>
struct test_is_specialized<Foo<float>> { };

struct not_specialized { };

template <typename T>
constexpr auto test_identity() -> bool
{
    using etl::is_same_v;
    using etl::type_identity;
    using etl::type_identity_t;

    CHECK(is_same_v<T, typename type_identity<T>::type>);
    CHECK(is_same_v<T, type_identity_t<T>>);

    // clang-format off
    if constexpr (!etl::is_function_v<T>) {
        CHECK(is_same_v<T const, typename type_identity<T const>::type>);
        CHECK(is_same_v<T volatile, typename type_identity<T volatile>::type>);
        CHECK(is_same_v<T const volatile, typename type_identity<T const volatile>::type>);

        CHECK(is_same_v<T const, type_identity_t<T const>>);
        CHECK(is_same_v<T volatile, type_identity_t<T volatile>>);
        CHECK(is_same_v<T const volatile, type_identity_t<T const volatile>>);
    }

    if constexpr (!etl::is_void_v<T>) {
        CHECK(is_same_v<T&, typename type_identity<T&>::type>);
        CHECK(is_same_v<T&&, typename type_identity<T&&>::type>);

        CHECK(is_same_v<T&, type_identity_t<T&>>);
        CHECK(is_same_v<T&&, type_identity_t<T&&>>);
    }

    if constexpr (!etl::is_void_v<T> && !etl::is_function_v<T>) {
        CHECK(is_same_v<T const&, typename type_identity<T const&>::type>);
        CHECK(is_same_v<T volatile&, typename type_identity<T volatile&>::type>);
        CHECK(is_same_v<T const volatile&, typename type_identity<T const volatile&>::type>);
        CHECK(is_same_v<T const&&, typename type_identity<T const&&>::type>);
        CHECK(is_same_v<T volatile&&, typename type_identity<T volatile&&>::type>);
        CHECK(is_same_v<T const volatile&&, typename type_identity<T const volatile&&>::type>);

        CHECK(is_same_v<T const&, type_identity_t<T const&>>);
        CHECK(is_same_v<T volatile&, type_identity_t<T volatile&>>);
        CHECK(is_same_v<T const volatile&, type_identity_t<T const volatile&>>);
        CHECK(is_same_v<T const&&, type_identity_t<T const&&>>);
        CHECK(is_same_v<T volatile&&, type_identity_t<T volatile&&>>);
        CHECK(is_same_v<T const volatile&&, type_identity_t<T const volatile&&>>);
    }

    // clang-format on
    return true;
}
} // namespace

template <typename T>
constexpr auto test() -> bool
{
    using etl::is_same;
    using etl::is_same_v;

    using TC  = T const;
    using TV  = T volatile;
    using TCV = T const volatile;

    TEST_TRAIT_VALUE_CV(rank, T, 0);
    TEST_TRAIT_VALUE_CV(rank, T[], 1);
    TEST_TRAIT_VALUE_CV(rank, T[1], 1);
    TEST_TRAIT_VALUE_CV(rank, T[1][2], 2);
    TEST_TRAIT_VALUE_CV(rank, T[1][2][3], 3);
    TEST_TRAIT_VALUE_CV(rank, T[1][2][3][4], 4);
    TEST_TRAIT_VALUE_CV(rank, T[1][2][3][4][5], 5);

    TEST_TRAIT_TYPE(remove_extent, T, T);
    TEST_TRAIT_TYPE(remove_extent, TC, TC);
    TEST_TRAIT_TYPE(remove_extent, TV, TV);
    TEST_TRAIT_TYPE(remove_extent, TCV, TCV);
    TEST_TRAIT_TYPE(remove_extent, T*, T*);
    TEST_TRAIT_TYPE(remove_extent, TC*, TC*);
    TEST_TRAIT_TYPE(remove_extent, TV*, TV*);
    TEST_TRAIT_TYPE(remove_extent, TCV*, TCV*);
    TEST_TRAIT_TYPE(remove_extent, T&, T&);
    TEST_TRAIT_TYPE(remove_extent, TC&, TC&);
    TEST_TRAIT_TYPE(remove_extent, TV&, TV&);
    TEST_TRAIT_TYPE(remove_extent, TCV&, TCV&);
    TEST_TRAIT_TYPE(remove_extent, T&&, T&&);
    TEST_TRAIT_TYPE(remove_extent, TC&&, TC&&);
    TEST_TRAIT_TYPE(remove_extent, TV&&, TV&&);
    TEST_TRAIT_TYPE(remove_extent, TCV&&, TCV&&);
    TEST_TRAIT_TYPE(remove_extent, T[], T);
    TEST_TRAIT_TYPE(remove_extent, TC[], TC);
    TEST_TRAIT_TYPE(remove_extent, TV[], TV);
    TEST_TRAIT_TYPE(remove_extent, TCV[], TCV);
    TEST_TRAIT_TYPE(remove_extent, T[2], T);
    TEST_TRAIT_TYPE(remove_extent, TC[2], TC);
    TEST_TRAIT_TYPE(remove_extent, TV[2], TV);
    TEST_TRAIT_TYPE(remove_extent, TCV[2], TCV);
    TEST_TRAIT_TYPE(remove_extent, T[2][4], T[4]);
    TEST_TRAIT_TYPE(remove_extent, TC[2][4], TC[4]);
    TEST_TRAIT_TYPE(remove_extent, TV[2][4], TV[4]);
    TEST_TRAIT_TYPE(remove_extent, TCV[2][4], TCV[4]);
    TEST_TRAIT_TYPE(remove_extent, T[2][4][8], T[4][8]);
    TEST_TRAIT_TYPE(remove_extent, TC[2][4][8], TC[4][8]);
    TEST_TRAIT_TYPE(remove_extent, TV[2][4][8], TV[4][8]);
    TEST_TRAIT_TYPE(remove_extent, TCV[2][4][8], TCV[4][8]);

    TEST_TRAIT_TYPE(remove_all_extents, T, T);
    TEST_TRAIT_TYPE(remove_all_extents, TC, TC);
    TEST_TRAIT_TYPE(remove_all_extents, TV, TV);
    TEST_TRAIT_TYPE(remove_all_extents, TCV, TCV);
    TEST_TRAIT_TYPE(remove_all_extents, T*, T*);
    TEST_TRAIT_TYPE(remove_all_extents, TC*, TC*);
    TEST_TRAIT_TYPE(remove_all_extents, TV*, TV*);
    TEST_TRAIT_TYPE(remove_all_extents, TCV*, TCV*);
    TEST_TRAIT_TYPE(remove_all_extents, T&, T&);
    TEST_TRAIT_TYPE(remove_all_extents, TC&, TC&);
    TEST_TRAIT_TYPE(remove_all_extents, TV&, TV&);
    TEST_TRAIT_TYPE(remove_all_extents, TCV&, TCV&);
    TEST_TRAIT_TYPE(remove_all_extents, T&&, T&&);
    TEST_TRAIT_TYPE(remove_all_extents, TC&&, TC&&);
    TEST_TRAIT_TYPE(remove_all_extents, TV&&, TV&&);
    TEST_TRAIT_TYPE(remove_all_extents, TCV&&, TCV&&);
    TEST_TRAIT_TYPE(remove_all_extents, T[], T);
    TEST_TRAIT_TYPE(remove_all_extents, TC[], TC);
    TEST_TRAIT_TYPE(remove_all_extents, TV[], TV);
    TEST_TRAIT_TYPE(remove_all_extents, TCV[], TCV);
    TEST_TRAIT_TYPE(remove_all_extents, T[2], T);
    TEST_TRAIT_TYPE(remove_all_extents, TC[2], TC);
    TEST_TRAIT_TYPE(remove_all_extents, TV[2], TV);
    TEST_TRAIT_TYPE(remove_all_extents, TCV[2], TCV);
    TEST_TRAIT_TYPE(remove_all_extents, T[2][4], T);
    TEST_TRAIT_TYPE(remove_all_extents, TC[2][4], TC);
    TEST_TRAIT_TYPE(remove_all_extents, TV[2][4], TV);
    TEST_TRAIT_TYPE(remove_all_extents, TCV[2][4], TCV);
    TEST_TRAIT_TYPE(remove_all_extents, T[2][4][8], T);
    TEST_TRAIT_TYPE(remove_all_extents, TC[2][4][8], TC);
    TEST_TRAIT_TYPE(remove_all_extents, TV[2][4][8], TV);
    TEST_TRAIT_TYPE(remove_all_extents, TCV[2][4][8], TCV);

    // TODO: Broken on MSVC
    //  CHECK(is_same_v<decay_t<T(T)>, T (*)(T)>);
    TEST_TRAIT_TYPE(decay, T, T);
    TEST_TRAIT_TYPE(decay, T&, T);
    TEST_TRAIT_TYPE(decay, T&&, T);
    TEST_TRAIT_TYPE(decay, T const&, T);
    TEST_TRAIT_TYPE(decay, T[2], T*);

    using etl::common_type_t;
    CHECK(is_same_v<common_type_t<T>, T>);
    CHECK(is_same_v<common_type_t<T, T>, T>);
    CHECK(is_same_v<common_type_t<T, T const>, T>);
    CHECK(is_same_v<common_type_t<T, T volatile>, T>);
    CHECK(is_same_v<common_type_t<T, T const volatile>, T>);
    CHECK(is_same_v<common_type_t<T, double>, double>);

    if constexpr (etl::is_integral_v<T>) {
        auto const constant = etl::integral_constant<T, T{0}>{};
        CHECK(decltype(constant)::value == T{0});
        CHECK(constant() == T{0});
        CHECK(static_cast<T>(constant) == T{0});
        CHECK(etl::is_same_v<T, typename decltype(constant)::value_type>);
    }

    // false
    {
        auto const constant = etl::bool_constant<false>{};
        CHECK(decltype(constant)::value == false);
        CHECK(constant() == false);
        CHECK(static_cast<bool>(constant) == false);
        CHECK(etl::is_same_v<bool, decltype(constant)::value_type>);
    }

    // true
    {
        auto const constant = etl::bool_constant<true>{};
        CHECK(decltype(constant)::value == true);
        CHECK(constant() == true);
        CHECK(static_cast<bool>(constant) == true);
        CHECK(etl::is_same_v<bool, decltype(constant)::value_type>);
    }

    // true_type
    {
        CHECK(etl::is_same_v<bool, etl::true_type::value_type>);
        CHECK(etl::true_type::value == true);
    }

    // false_type
    {
        CHECK(etl::is_same_v<bool, etl::false_type::value_type>);
        CHECK(etl::false_type::value == false);
    }

    CHECK(etl::is_same_v<struct S, T> == false);
    CHECK(etl::is_same_v<struct S, T> == false);
    CHECK(etl::is_same<T, T>::value == true);

    TEST_IS_TRAIT_CV(is_void, void);
    TEST_IS_TRAIT_CV_FALSE(is_void, T);
    TEST_IS_TRAIT_CV_FALSE(is_void, T*);
    TEST_IS_TRAIT_CV_FALSE(is_void, T&);
    TEST_IS_TRAIT_CV_FALSE(is_void, T&&);

    TEST_IS_TRAIT(is_const, TC);
    TEST_IS_TRAIT(is_const, TCV);
    TEST_IS_TRAIT(is_const, void const);
    TEST_IS_TRAIT(is_const, void const volatile);
    TEST_IS_TRAIT_FALSE(is_const, T);
    TEST_IS_TRAIT_FALSE(is_const, TV);
    TEST_IS_TRAIT_FALSE(is_const, void);
    TEST_IS_TRAIT_FALSE(is_const, void volatile);

    TEST_IS_TRAIT(is_volatile, TV);
    TEST_IS_TRAIT(is_volatile, TCV);
    TEST_IS_TRAIT(is_volatile, void volatile);
    TEST_IS_TRAIT(is_volatile, void const volatile);
    TEST_IS_TRAIT_FALSE(is_volatile, T);
    TEST_IS_TRAIT_FALSE(is_volatile, TC);
    TEST_IS_TRAIT_FALSE(is_volatile, void);
    TEST_IS_TRAIT_FALSE(is_volatile, void const);

    using etl::is_convertible_v;

    CHECK(is_convertible_v<void, void>);

    // TODO: [tobi] The assertions below trigger an internal compiler error on
    // MSVC
    #if not defined(TETL_MSVC)

    CHECK(!(is_convertible_v<int, void>));
    CHECK(!(is_convertible_v<int, void const>));

    CHECK(is_convertible_v<void, void const>);
    CHECK(is_convertible_v<void const, void>);
    CHECK(is_convertible_v<void const, void const>);

        #if TETL_CPP_STANDARD < 20
    CHECK(!(is_convertible_v<int, void volatile>));
    CHECK(!(is_convertible_v<int, void const volatile>));
    CHECK(is_convertible_v<void, void volatile>);
    CHECK(is_convertible_v<void, void const volatile>);
    CHECK(is_convertible_v<void const, void volatile>);
    CHECK(is_convertible_v<void const, void const volatile>);
    CHECK(is_convertible_v<void volatile, void volatile>);
    CHECK(is_convertible_v<void volatile, void const volatile>);
    CHECK(is_convertible_v<void volatile, void>);
    CHECK(is_convertible_v<void volatile, void const>);
    CHECK(is_convertible_v<void const volatile, void>);
    CHECK(is_convertible_v<void const volatile, void const>);
    CHECK(is_convertible_v<void const volatile, void volatile>);
    CHECK(is_convertible_v<void const volatile, void const volatile>);
        #endif

    #endif

    TEST_IS_TRAIT_CV(is_arithmetic, bool);
    TEST_IS_TRAIT_CV(is_arithmetic, T);
    TEST_IS_TRAIT_CV_FALSE(is_arithmetic, T*);
    TEST_IS_TRAIT_CV_FALSE(is_arithmetic, T&);

    TEST_IS_TRAIT_CV(is_scalar, etl::nullptr_t);
    TEST_IS_TRAIT_CV(is_scalar, etl::nullptr_t*);
    TEST_IS_TRAIT_CV(is_scalar, bool);
    TEST_IS_TRAIT_CV(is_scalar, bool*);
    TEST_IS_TRAIT_CV(is_scalar, T);
    TEST_IS_TRAIT_CV(is_scalar, T*);
    TEST_IS_TRAIT_CV(is_scalar, T* const);
    TEST_IS_TRAIT_CV_FALSE(is_scalar, T&);

    TEST_IS_TRAIT_CV(is_object, T);
    TEST_IS_TRAIT_CV(is_object, T*);
    TEST_IS_TRAIT_CV(is_object, T* const);
    TEST_IS_TRAIT_CV(is_object, T* const);
    TEST_IS_TRAIT_CV_FALSE(is_object, T&);

    TEST_IS_TRAIT_CV(is_reference, T&);
    TEST_IS_TRAIT_CV(is_reference, T&&);
    TEST_IS_TRAIT_CV_FALSE(is_reference, T*);
    TEST_IS_TRAIT_CV_FALSE(is_reference, T);

    TEST_IS_TRAIT_CV(is_lvalue_reference, T&);
    TEST_IS_TRAIT_CV_FALSE(is_lvalue_reference, T);
    TEST_IS_TRAIT_CV_FALSE(is_lvalue_reference, T*);
    TEST_IS_TRAIT_CV_FALSE(is_lvalue_reference, T&&);

    TEST_IS_TRAIT_CV(is_rvalue_reference, T&&);
    TEST_IS_TRAIT_CV_FALSE(is_rvalue_reference, T);
    TEST_IS_TRAIT_CV_FALSE(is_rvalue_reference, T*);
    TEST_IS_TRAIT_CV_FALSE(is_rvalue_reference, T&);

    TEST_IS_TRAIT_CV(is_fundamental, void);
    TEST_IS_TRAIT_CV(is_fundamental, bool);
    TEST_IS_TRAIT_CV(is_fundamental, etl::nullptr_t);
    TEST_IS_TRAIT_CV(is_fundamental, T);
    TEST_IS_TRAIT_CV_FALSE(is_fundamental, T*);
    TEST_IS_TRAIT_CV_FALSE(is_fundamental, T&);
    TEST_IS_TRAIT_CV_FALSE(is_fundamental, T&&);

    TEST_IS_TRAIT_CV(is_bounded_array, T[1]);
    TEST_IS_TRAIT_CV(is_bounded_array, T[2]);
    TEST_IS_TRAIT_CV(is_bounded_array, T[32]);
    TEST_IS_TRAIT_CV(is_bounded_array, T[64]);
    TEST_IS_TRAIT_CV_FALSE(is_bounded_array, T);
    TEST_IS_TRAIT_CV_FALSE(is_bounded_array, T*);
    TEST_IS_TRAIT_CV_FALSE(is_bounded_array, T&);
    TEST_IS_TRAIT_CV_FALSE(is_bounded_array, T&&);
    TEST_IS_TRAIT_CV_FALSE(is_bounded_array, T[]);
    TEST_IS_TRAIT_CV_FALSE(is_bounded_array, T(&)[3]);
    TEST_IS_TRAIT_CV_FALSE(is_bounded_array, T(&)[]);
    TEST_IS_TRAIT_CV_FALSE(is_bounded_array, T(&&)[3]);
    TEST_IS_TRAIT_CV_FALSE(is_bounded_array, T(&&)[]);

    TEST_IS_TRAIT_CV(is_unbounded_array, T[]);
    TEST_IS_TRAIT_CV_FALSE(is_unbounded_array, T[64]);
    TEST_IS_TRAIT_CV_FALSE(is_unbounded_array, T);
    TEST_IS_TRAIT_CV_FALSE(is_unbounded_array, T*);
    TEST_IS_TRAIT_CV_FALSE(is_unbounded_array, T&);
    TEST_IS_TRAIT_CV_FALSE(is_unbounded_array, T&&);
    TEST_IS_TRAIT_CV_FALSE(is_unbounded_array, T(&)[3]);
    TEST_IS_TRAIT_CV_FALSE(is_unbounded_array, T(&)[]);
    TEST_IS_TRAIT_CV_FALSE(is_unbounded_array, T(&&)[3]);
    TEST_IS_TRAIT_CV_FALSE(is_unbounded_array, T(&&)[]);

    TEST_IS_TRAIT_CV(is_array, T[]);
    TEST_IS_TRAIT_CV(is_array, T[1]);
    TEST_IS_TRAIT_CV(is_array, T[1][2]);
    TEST_IS_TRAIT_CV_FALSE(is_array, etl::nullptr_t);
    TEST_IS_TRAIT_CV_FALSE(is_array, T);

    TEST_IS_TRAIT_CV(is_null_pointer, etl::nullptr_t);
    TEST_IS_TRAIT_CV_FALSE(is_null_pointer, T);

    TEST_IS_TRAIT_CV(is_pointer, T*);
    TEST_IS_TRAIT_CV_FALSE(is_pointer, T);
    TEST_IS_TRAIT_CV_FALSE(is_pointer, T&);
    TEST_IS_TRAIT_CV_FALSE(is_pointer, T&&);

    TEST_IS_TRAIT_CV(has_virtual_destructor, VirtualDtor);
    TEST_IS_TRAIT_CV(has_virtual_destructor, Abstract);
    TEST_IS_TRAIT_CV_FALSE(has_virtual_destructor, EmptyClass);
    TEST_IS_TRAIT_CV_FALSE(has_virtual_destructor, T);
    TEST_IS_TRAIT_CV_FALSE(has_virtual_destructor, T*);
    TEST_IS_TRAIT_CV_FALSE(has_virtual_destructor, T&);
    TEST_IS_TRAIT_CV_FALSE(has_virtual_destructor, T&&);
    TEST_IS_TRAIT_CV_FALSE(has_virtual_destructor, etl::nullptr_t);

    TEST_TRAIT_TYPE(remove_volatile, TV, T);
    TEST_TRAIT_TYPE(remove_volatile, T, T);
    TEST_TRAIT_TYPE(remove_volatile, TC, TC);
    TEST_TRAIT_TYPE(remove_volatile, TCV, TC);

    TEST_TRAIT_TYPE(add_volatile, T, TV);
    TEST_TRAIT_TYPE(add_volatile, TV, TV);
    TEST_TRAIT_TYPE(add_volatile, TC, TCV);
    TEST_TRAIT_TYPE(add_volatile, TCV, TCV);
    TEST_TRAIT_TYPE(add_volatile, T[42], TV[42]);
    TEST_TRAIT_TYPE(add_volatile, TC[42], TCV[42]);
    TEST_TRAIT_TYPE(add_volatile, TV[42], TV[42]);
    TEST_TRAIT_TYPE(add_volatile, TCV[42], TCV[42]);
    TEST_TRAIT_TYPE(add_volatile, T[], TV[]);
    TEST_TRAIT_TYPE(add_volatile, TC[], TCV[]);
    TEST_TRAIT_TYPE(add_volatile, TV[], TV[]);
    TEST_TRAIT_TYPE(add_volatile, TCV[], TCV[]);

    TEST_TRAIT_TYPE(remove_const, TC, T);
    TEST_TRAIT_TYPE(remove_const, T, T);
    TEST_TRAIT_TYPE(remove_const, TV, TV);
    TEST_TRAIT_TYPE(remove_const, TCV, TV);
    TEST_TRAIT_TYPE(remove_const, T&, T&);
    TEST_TRAIT_TYPE(remove_const, TC&, TC&);
    TEST_TRAIT_TYPE(remove_const, TV&, TV&);
    TEST_TRAIT_TYPE(remove_const, TCV&, TCV&);
    TEST_TRAIT_TYPE(remove_const, T&&, T&&);
    TEST_TRAIT_TYPE(remove_const, TC&&, TC&&);
    TEST_TRAIT_TYPE(remove_const, TV&&, TV&&);
    TEST_TRAIT_TYPE(remove_const, TCV&&, TCV&&);
    TEST_TRAIT_TYPE(remove_const, T[42], T[42]);
    TEST_TRAIT_TYPE(remove_const, TC[42], T[42]);
    TEST_TRAIT_TYPE(remove_const, TV[42], TV[42]);
    TEST_TRAIT_TYPE(remove_const, TCV[42], TV[42]);
    TEST_TRAIT_TYPE(remove_const, T[], T[]);
    TEST_TRAIT_TYPE(remove_const, TC[], T[]);
    TEST_TRAIT_TYPE(remove_const, TV[], TV[]);
    TEST_TRAIT_TYPE(remove_const, TCV[], TV[]);

    TEST_TRAIT_TYPE(add_const, T, TC);
    TEST_TRAIT_TYPE(add_const, TV, TCV);
    TEST_TRAIT_TYPE(add_const, TC, TC);
    TEST_TRAIT_TYPE(add_const, TCV, TCV);
    TEST_TRAIT_TYPE(add_const, T[42], TC[42]);
    TEST_TRAIT_TYPE(add_const, TC[42], TC[42]);
    TEST_TRAIT_TYPE(add_const, TV[42], TCV[42]);
    TEST_TRAIT_TYPE(add_const, TCV[42], TCV[42]);
    TEST_TRAIT_TYPE(add_const, T[], TC[]);
    TEST_TRAIT_TYPE(add_const, TC[], TC[]);
    TEST_TRAIT_TYPE(add_const, TV[], TCV[]);
    TEST_TRAIT_TYPE(add_const, TCV[], TCV[]);

    TEST_TRAIT_TYPE(remove_cv, TC, T);
    TEST_TRAIT_TYPE(remove_cv, T, T);
    TEST_TRAIT_TYPE(remove_cv, TV, T);
    TEST_TRAIT_TYPE(remove_cv, TCV, T);
    TEST_TRAIT_TYPE(remove_cv, T[42], T[42]);
    TEST_TRAIT_TYPE(remove_cv, TC[42], T[42]);
    TEST_TRAIT_TYPE(remove_cv, TV[42], T[42]);
    TEST_TRAIT_TYPE(remove_cv, TCV[42], T[42]);
    TEST_TRAIT_TYPE(remove_cv, T[], T[]);
    TEST_TRAIT_TYPE(remove_cv, TC[], T[]);
    TEST_TRAIT_TYPE(remove_cv, TV[], T[]);
    TEST_TRAIT_TYPE(remove_cv, TCV[], T[]);
    TEST_TRAIT_TYPE(remove_cv, T&, T&);
    TEST_TRAIT_TYPE(remove_cv, TC&, TC&);
    TEST_TRAIT_TYPE(remove_cv, TV&, TV&);
    TEST_TRAIT_TYPE(remove_cv, TCV&, TCV&);
    TEST_TRAIT_TYPE(remove_cv, T&&, T&&);
    TEST_TRAIT_TYPE(remove_cv, TC&&, TC&&);
    TEST_TRAIT_TYPE(remove_cv, TV&&, TV&&);
    TEST_TRAIT_TYPE(remove_cv, TCV&&, TCV&&);

    TEST_TRAIT_TYPE(add_cv, T, TCV);
    TEST_TRAIT_TYPE(add_cv, TV, TCV);
    TEST_TRAIT_TYPE(add_cv, TC, TCV);
    TEST_TRAIT_TYPE(add_cv, TCV, TCV);
    TEST_TRAIT_TYPE(add_cv, T[42], TCV[42]);
    TEST_TRAIT_TYPE(add_cv, TC[42], TCV[42]);
    TEST_TRAIT_TYPE(add_cv, TV[42], TCV[42]);
    TEST_TRAIT_TYPE(add_cv, TCV[42], TCV[42]);
    TEST_TRAIT_TYPE(add_cv, T[], TCV[]);
    TEST_TRAIT_TYPE(add_cv, TC[], TCV[]);
    TEST_TRAIT_TYPE(add_cv, TV[], TCV[]);
    TEST_TRAIT_TYPE(add_cv, TCV[], TCV[]);

    TEST_TRAIT_TYPE(remove_cvref, T, T);
    TEST_TRAIT_TYPE(remove_cvref, TC, T);
    TEST_TRAIT_TYPE(remove_cvref, TV, T);
    TEST_TRAIT_TYPE(remove_cvref, TCV, T);
    TEST_TRAIT_TYPE(remove_cvref, T[42], T[42]);
    TEST_TRAIT_TYPE(remove_cvref, TC[42], T[42]);
    TEST_TRAIT_TYPE(remove_cvref, TV[42], T[42]);
    TEST_TRAIT_TYPE(remove_cvref, TCV[42], T[42]);
    TEST_TRAIT_TYPE(remove_cvref, T[], T[]);
    TEST_TRAIT_TYPE(remove_cvref, TC[], T[]);
    TEST_TRAIT_TYPE(remove_cvref, TV[], T[]);
    TEST_TRAIT_TYPE(remove_cvref, TCV[], T[]);
    TEST_TRAIT_TYPE(remove_cvref, T&, T);
    TEST_TRAIT_TYPE(remove_cvref, TC&, T);
    TEST_TRAIT_TYPE(remove_cvref, TV&, T);
    TEST_TRAIT_TYPE(remove_cvref, TCV&, T);
    TEST_TRAIT_TYPE(remove_cvref, T&&, T);
    TEST_TRAIT_TYPE(remove_cvref, TC&&, T);
    TEST_TRAIT_TYPE(remove_cvref, TV&&, T);
    TEST_TRAIT_TYPE(remove_cvref, TCV&&, T);

    TEST_TRAIT_TYPE(add_pointer, T, T*);
    TEST_TRAIT_TYPE(add_pointer, TV, TV*);
    TEST_TRAIT_TYPE(add_pointer, TC, TC*);
    TEST_TRAIT_TYPE(add_pointer, TCV, TCV*);
    TEST_TRAIT_TYPE(remove_pointer, T*, T);
    TEST_TRAIT_TYPE(remove_pointer, TC*, TC);
    TEST_TRAIT_TYPE(remove_pointer, TV*, TV);
    TEST_TRAIT_TYPE(remove_pointer, TCV*, TCV);

    TEST_TRAIT_TYPE(remove_reference, T, T);
    TEST_TRAIT_TYPE(remove_reference, T*, T*);
    TEST_TRAIT_TYPE(remove_reference, T&, T);
    TEST_TRAIT_TYPE(remove_reference, TC&, TC);
    TEST_TRAIT_TYPE(remove_reference, TV&, TV);
    TEST_TRAIT_TYPE(remove_reference, TCV&, TCV);
    TEST_TRAIT_TYPE(remove_reference, T&&, T);
    TEST_TRAIT_TYPE(remove_reference, TC&&, TC);
    TEST_TRAIT_TYPE(remove_reference, TV&&, TV);
    TEST_TRAIT_TYPE(remove_reference, TCV&&, TCV);

    // clang-format off
    TEST_TRAIT_TYPE(add_lvalue_reference, T, T&);
    TEST_TRAIT_TYPE(add_lvalue_reference, TC, TC&);
    TEST_TRAIT_TYPE(add_lvalue_reference, TV, TV&);
    TEST_TRAIT_TYPE(add_lvalue_reference, TCV, TCV&);
    TEST_TRAIT_TYPE(add_lvalue_reference, void, void);
    TEST_TRAIT_TYPE(add_lvalue_reference, void const, void const);
    TEST_TRAIT_TYPE(add_lvalue_reference, void volatile, void volatile);
    TEST_TRAIT_TYPE(add_lvalue_reference, void const volatile, void const volatile);
    // clang-format on

    TEST_TRAIT_TYPE(add_rvalue_reference, T, T&&);
    TEST_TRAIT_TYPE(add_rvalue_reference, TC, TC&&);
    TEST_TRAIT_TYPE(add_rvalue_reference, TV, TV&&);
    TEST_TRAIT_TYPE(add_rvalue_reference, TCV, TCV&&);

    TEST_IS_TRAIT_CV(is_trivial, T*);
    TEST_IS_TRAIT_CV_FALSE(is_trivial, T&);

    TEST_IS_TRAIT(is_swappable, T);
    TEST_IS_TRAIT_CV(is_swappable, T*);
    TEST_IS_TRAIT_CV(is_swappable, void*);

    // clang-format off
    CHECK(test_identity<void>());
    CHECK(test_identity<T>());
    CHECK(test_identity<T*>());
    CHECK(test_identity<T const*>());
    CHECK(test_identity<T volatile*>());
    CHECK(test_identity<T const volatile*>());
    CHECK(test_identity<T[3]>());
    CHECK(test_identity<T[]>());
    CHECK(test_identity<T(T)>());
    CHECK(test_identity<T&(T)>());
    CHECK(test_identity<T const&(T)>());
    CHECK(test_identity<T volatile&(T)>());
    CHECK(test_identity<T const volatile&(T)>());
    CHECK(test_identity<T(T&)>());
    CHECK(test_identity<T(T const&)>());
    CHECK(test_identity<T(T volatile&)>());
    CHECK(test_identity<T(T const volatile&)>());
    CHECK(test_identity<T IDS::*>());
    CHECK(test_identity<T const IDS::*>());
    CHECK(test_identity<T volatile IDS::*>());
    CHECK(test_identity<T const volatile IDS::*>());
    CHECK(test_identity<T (IDS::*)(T)>());
    CHECK(test_identity<T (IDS::*)(T&)>());
    CHECK(test_identity<T (IDS::*)(T const&) const>());
    CHECK(test_identity<T (IDS::*)(T volatile&) volatile>());
    CHECK(test_identity<T (IDS::*)(T const volatile&) const volatile>());
    CHECK(test_identity<T (IDS::*)(T)&>());
    CHECK(test_identity<T (IDS::*)(T) const&>());
    CHECK(test_identity<T (IDS::*)(T) &&>());
    CHECK(test_identity<T (IDS::*)(T) const&&>());
    CHECK(test_identity<T& (IDS::*)(T)>());
    CHECK(test_identity<T const& (IDS::*)(T)>());
    CHECK(test_identity<T volatile& (IDS::*)(T)>());
    CHECK(test_identity<T const volatile& (IDS::*)(T)>());
    // clang-format on

    CHECK(sizeof(etl::aligned_union_t<0, char>) == 1);
    CHECK(sizeof(etl::aligned_union_t<2, char>) == 2);
    CHECK(sizeof(etl::aligned_union_t<2, char[3]>) == 3);
    CHECK(sizeof(etl::aligned_union_t<3, char[4]>) == 4);
    CHECK(sizeof(etl::aligned_union_t<1, char, T, double>) == 8);
    CHECK(sizeof(etl::aligned_union_t<12, char, T, double>) == 16);

    using etl::type_pack_element_t;
    CHECK(is_same_v<type_pack_element_t<0, T>, T>);
    CHECK(is_same_v<type_pack_element_t<1, T, float>, float>);
    CHECK(is_same_v<type_pack_element_t<2, T, char, short>, short>);

    CHECK(etl::is_specialized_v<test_is_specialized, Foo<float>>);
    CHECK(!(etl::is_specialized_v<test_is_specialized, T>));
    CHECK(!(etl::is_specialized_v<test_is_specialized, double>));

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test<char>());
    CHECK(test<etl::uint8_t>());
    CHECK(test<etl::int8_t>());
    CHECK(test<etl::uint16_t>());
    CHECK(test<etl::int16_t>());
    CHECK(test<etl::uint32_t>());
    CHECK(test<etl::int32_t>());
    CHECK(test<etl::uint64_t>());
    CHECK(test<etl::int64_t>());

    CHECK(test<float>());
    CHECK(test<double>());
    // CHECK(test<long double>());

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
