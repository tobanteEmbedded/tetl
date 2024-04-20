// SPDX-License-Identifier: BSL-1.0

#include <etl/type_traits.hpp>

#include <etl/cstdint.hpp>
#include <etl/version.hpp>

#include "testing/testing.hpp"
#include "testing/types.hpp"

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
    CHECK_SAME_TYPE(T, typename etl::type_identity<T>::type);
    CHECK_SAME_TYPE(T, etl::type_identity_t<T>);

    if constexpr (not etl::is_function_v<T>) {
        CHECK_SAME_TYPE(T const, typename etl::type_identity<T const>::type);
        CHECK_SAME_TYPE(T volatile, typename etl::type_identity<T volatile>::type);
        CHECK_SAME_TYPE(T const volatile, typename etl::type_identity<T const volatile>::type);

        CHECK_SAME_TYPE(T const, etl::type_identity_t<T const>);
        CHECK_SAME_TYPE(T volatile, etl::type_identity_t<T volatile>);
        CHECK_SAME_TYPE(T const volatile, etl::type_identity_t<T const volatile>);
    }

    if constexpr (not etl::is_void_v<T>) {
        CHECK_SAME_TYPE(T&, typename etl::type_identity<T&>::type);
        CHECK_SAME_TYPE(T&&, typename etl::type_identity<T&&>::type);

        CHECK_SAME_TYPE(T&, etl::type_identity_t<T&>);
        CHECK_SAME_TYPE(T&&, etl::type_identity_t<T&&>);
    }

    if constexpr (not etl::is_void_v<T> and not etl::is_function_v<T>) {
        CHECK_SAME_TYPE(T const&, typename etl::type_identity<T const&>::type);
        CHECK_SAME_TYPE(T volatile&, typename etl::type_identity<T volatile&>::type);
        CHECK_SAME_TYPE(T const volatile&, typename etl::type_identity<T const volatile&>::type);
        CHECK_SAME_TYPE(T const&&, typename etl::type_identity<T const&&>::type);
        CHECK_SAME_TYPE(T volatile&&, typename etl::type_identity<T volatile&&>::type);
        CHECK_SAME_TYPE(T const volatile&&, typename etl::type_identity<T const volatile&&>::type);

        CHECK_SAME_TYPE(T const&, etl::type_identity_t<T const&>);
        CHECK_SAME_TYPE(T volatile&, etl::type_identity_t<T volatile&>);
        CHECK_SAME_TYPE(T const volatile&, etl::type_identity_t<T const volatile&>);
        CHECK_SAME_TYPE(T const&&, etl::type_identity_t<T const&&>);
        CHECK_SAME_TYPE(T volatile&&, etl::type_identity_t<T volatile&&>);
        CHECK_SAME_TYPE(T const volatile&&, etl::type_identity_t<T const volatile&&>);
    }

    return true;
}
} // namespace

template <typename T>
constexpr auto test() -> bool
{
    using TC  = T const;
    using TV  = T volatile;
    using TCV = T const volatile;

    CHECK_TRAIT_VALUE_CV(rank, T, 0);
    CHECK_TRAIT_VALUE_CV(rank, T[], 1);
    CHECK_TRAIT_VALUE_CV(rank, T[1], 1);
    CHECK_TRAIT_VALUE_CV(rank, T[1][2], 2);
    CHECK_TRAIT_VALUE_CV(rank, T[1][2][3], 3);
    CHECK_TRAIT_VALUE_CV(rank, T[1][2][3][4], 4);
    CHECK_TRAIT_VALUE_CV(rank, T[1][2][3][4][5], 5);

    CHECK_TRAIT_TYPE(remove_extent, T, T);
    CHECK_TRAIT_TYPE(remove_extent, TC, TC);
    CHECK_TRAIT_TYPE(remove_extent, TV, TV);
    CHECK_TRAIT_TYPE(remove_extent, TCV, TCV);
    CHECK_TRAIT_TYPE(remove_extent, T*, T*);
    CHECK_TRAIT_TYPE(remove_extent, TC*, TC*);
    CHECK_TRAIT_TYPE(remove_extent, TV*, TV*);
    CHECK_TRAIT_TYPE(remove_extent, TCV*, TCV*);
    CHECK_TRAIT_TYPE(remove_extent, T&, T&);
    CHECK_TRAIT_TYPE(remove_extent, TC&, TC&);
    CHECK_TRAIT_TYPE(remove_extent, TV&, TV&);
    CHECK_TRAIT_TYPE(remove_extent, TCV&, TCV&);
    CHECK_TRAIT_TYPE(remove_extent, T&&, T&&);
    CHECK_TRAIT_TYPE(remove_extent, TC&&, TC&&);
    CHECK_TRAIT_TYPE(remove_extent, TV&&, TV&&);
    CHECK_TRAIT_TYPE(remove_extent, TCV&&, TCV&&);
    CHECK_TRAIT_TYPE(remove_extent, T[], T);
    CHECK_TRAIT_TYPE(remove_extent, TC[], TC);
    CHECK_TRAIT_TYPE(remove_extent, TV[], TV);
    CHECK_TRAIT_TYPE(remove_extent, TCV[], TCV);
    CHECK_TRAIT_TYPE(remove_extent, T[2], T);
    CHECK_TRAIT_TYPE(remove_extent, TC[2], TC);
    CHECK_TRAIT_TYPE(remove_extent, TV[2], TV);
    CHECK_TRAIT_TYPE(remove_extent, TCV[2], TCV);
    CHECK_TRAIT_TYPE(remove_extent, T[2][4], T[4]);
    CHECK_TRAIT_TYPE(remove_extent, TC[2][4], TC[4]);
    CHECK_TRAIT_TYPE(remove_extent, TV[2][4], TV[4]);
    CHECK_TRAIT_TYPE(remove_extent, TCV[2][4], TCV[4]);
    CHECK_TRAIT_TYPE(remove_extent, T[2][4][8], T[4][8]);
    CHECK_TRAIT_TYPE(remove_extent, TC[2][4][8], TC[4][8]);
    CHECK_TRAIT_TYPE(remove_extent, TV[2][4][8], TV[4][8]);
    CHECK_TRAIT_TYPE(remove_extent, TCV[2][4][8], TCV[4][8]);

    CHECK_TRAIT_TYPE(remove_all_extents, T, T);
    CHECK_TRAIT_TYPE(remove_all_extents, TC, TC);
    CHECK_TRAIT_TYPE(remove_all_extents, TV, TV);
    CHECK_TRAIT_TYPE(remove_all_extents, TCV, TCV);
    CHECK_TRAIT_TYPE(remove_all_extents, T*, T*);
    CHECK_TRAIT_TYPE(remove_all_extents, TC*, TC*);
    CHECK_TRAIT_TYPE(remove_all_extents, TV*, TV*);
    CHECK_TRAIT_TYPE(remove_all_extents, TCV*, TCV*);
    CHECK_TRAIT_TYPE(remove_all_extents, T&, T&);
    CHECK_TRAIT_TYPE(remove_all_extents, TC&, TC&);
    CHECK_TRAIT_TYPE(remove_all_extents, TV&, TV&);
    CHECK_TRAIT_TYPE(remove_all_extents, TCV&, TCV&);
    CHECK_TRAIT_TYPE(remove_all_extents, T&&, T&&);
    CHECK_TRAIT_TYPE(remove_all_extents, TC&&, TC&&);
    CHECK_TRAIT_TYPE(remove_all_extents, TV&&, TV&&);
    CHECK_TRAIT_TYPE(remove_all_extents, TCV&&, TCV&&);
    CHECK_TRAIT_TYPE(remove_all_extents, T[], T);
    CHECK_TRAIT_TYPE(remove_all_extents, TC[], TC);
    CHECK_TRAIT_TYPE(remove_all_extents, TV[], TV);
    CHECK_TRAIT_TYPE(remove_all_extents, TCV[], TCV);
    CHECK_TRAIT_TYPE(remove_all_extents, T[2], T);
    CHECK_TRAIT_TYPE(remove_all_extents, TC[2], TC);
    CHECK_TRAIT_TYPE(remove_all_extents, TV[2], TV);
    CHECK_TRAIT_TYPE(remove_all_extents, TCV[2], TCV);
    CHECK_TRAIT_TYPE(remove_all_extents, T[2][4], T);
    CHECK_TRAIT_TYPE(remove_all_extents, TC[2][4], TC);
    CHECK_TRAIT_TYPE(remove_all_extents, TV[2][4], TV);
    CHECK_TRAIT_TYPE(remove_all_extents, TCV[2][4], TCV);
    CHECK_TRAIT_TYPE(remove_all_extents, T[2][4][8], T);
    CHECK_TRAIT_TYPE(remove_all_extents, TC[2][4][8], TC);
    CHECK_TRAIT_TYPE(remove_all_extents, TV[2][4][8], TV);
    CHECK_TRAIT_TYPE(remove_all_extents, TCV[2][4][8], TCV);

    // TODO: Broken on MSVC
    //  CHECK_SAME_TYPE(decay_t<T(T)>, T (*)(T));
    CHECK_TRAIT_TYPE(decay, T, T);
    CHECK_TRAIT_TYPE(decay, T&, T);
    CHECK_TRAIT_TYPE(decay, T&&, T);
    CHECK_TRAIT_TYPE(decay, T const&, T);
    CHECK_TRAIT_TYPE(decay, T[2], T*);

    CHECK_SAME_TYPE(etl::common_type_t<T>, T);
    CHECK_SAME_TYPE(etl::common_type_t<T, T>, T);
    CHECK_SAME_TYPE(etl::common_type_t<T, T const>, T);
    CHECK_SAME_TYPE(etl::common_type_t<T, T volatile>, T);
    CHECK_SAME_TYPE(etl::common_type_t<T, T const volatile>, T);
    CHECK_SAME_TYPE(etl::common_type_t<T, double>, double);

    if constexpr (etl::is_integral_v<T>) {
        auto const constant = etl::integral_constant<T, T{0}>{};
        CHECK(decltype(constant)::value == T{0});
        CHECK(constant() == T{0});
        CHECK(static_cast<T>(constant) == T{0});
        CHECK_SAME_TYPE(T, typename decltype(constant)::value_type);
    }

    // false
    {
        auto const constant = etl::bool_constant<false>{};
        CHECK(decltype(constant)::value == false);
        CHECK(constant() == false);
        CHECK(static_cast<bool>(constant) == false);
        CHECK_SAME_TYPE(bool, decltype(constant)::value_type);
    }

    // true
    {
        auto const constant = etl::bool_constant<true>{};
        CHECK(decltype(constant)::value == true);
        CHECK(constant() == true);
        CHECK(static_cast<bool>(constant) == true);
        CHECK_SAME_TYPE(bool, decltype(constant)::value_type);
    }

    // true_type
    {
        CHECK_SAME_TYPE(bool, etl::true_type::value_type);
        CHECK(etl::true_type::value == true);
    }

    // false_type
    {
        CHECK_SAME_TYPE(bool, etl::false_type::value_type);
        CHECK(etl::false_type::value == false);
    }

    CHECK(etl::is_same_v<struct S, T> == false);
    CHECK(etl::is_same_v<struct S, T> == false);
    CHECK(etl::is_same<T, T>::value == true);

    CHECK_IS_TRAIT_CV(is_void, void);
    CHECK_IS_TRAIT_CV_FALSE(is_void, T);
    CHECK_IS_TRAIT_CV_FALSE(is_void, T*);
    CHECK_IS_TRAIT_CV_FALSE(is_void, T&);
    CHECK_IS_TRAIT_CV_FALSE(is_void, T&&);

    CHECK_IS_TRAIT(is_const, TC);
    CHECK_IS_TRAIT(is_const, TCV);
    CHECK_IS_TRAIT(is_const, void const);
    CHECK_IS_TRAIT(is_const, void const volatile);
    CHECK_IS_TRAIT_FALSE(is_const, T);
    CHECK_IS_TRAIT_FALSE(is_const, TV);
    CHECK_IS_TRAIT_FALSE(is_const, void);
    CHECK_IS_TRAIT_FALSE(is_const, void volatile);

    CHECK_IS_TRAIT(is_volatile, TV);
    CHECK_IS_TRAIT(is_volatile, TCV);
    CHECK_IS_TRAIT(is_volatile, void volatile);
    CHECK_IS_TRAIT(is_volatile, void const volatile);
    CHECK_IS_TRAIT_FALSE(is_volatile, T);
    CHECK_IS_TRAIT_FALSE(is_volatile, TC);
    CHECK_IS_TRAIT_FALSE(is_volatile, void);
    CHECK_IS_TRAIT_FALSE(is_volatile, void const);

    CHECK(etl::is_convertible_v<void, void>);

// TODO: [tobi] The assertions below trigger an internal compiler error on
// MSVC
#if not defined(TETL_COMPILER_MSVC)

    CHECK_FALSE(etl::is_convertible_v<int, void>);
    CHECK_FALSE(etl::is_convertible_v<int, void const>);

    CHECK(etl::is_convertible_v<void, void const>);
    CHECK(etl::is_convertible_v<void const, void>);
    CHECK(etl::is_convertible_v<void const, void const>);

    #if TETL_CPP_STANDARD < 20
    CHECK_FALSE(etl::is_convertible_v<int, void volatile>);
    CHECK_FALSE(etl::is_convertible_v<int, void const volatile>);
    CHECK(etl::is_convertible_v<void, void volatile>);
    CHECK(etl::is_convertible_v<void, void const volatile>);
    CHECK(etl::is_convertible_v<void const, void volatile>);
    CHECK(etl::is_convertible_v<void const, void const volatile>);
    CHECK(etl::is_convertible_v<void volatile, void volatile>);
    CHECK(etl::is_convertible_v<void volatile, void const volatile>);
    CHECK(etl::is_convertible_v<void volatile, void>);
    CHECK(etl::is_convertible_v<void volatile, void const>);
    CHECK(etl::is_convertible_v<void const volatile, void>);
    CHECK(etl::is_convertible_v<void const volatile, void const>);
    CHECK(etl::is_convertible_v<void const volatile, void volatile>);
    CHECK(etl::is_convertible_v<void const volatile, void const volatile>);
    #endif

#endif

    CHECK_IS_TRAIT_CV(is_arithmetic, bool);
    CHECK_IS_TRAIT_CV(is_arithmetic, T);
    CHECK_IS_TRAIT_CV_FALSE(is_arithmetic, T*);
    CHECK_IS_TRAIT_CV_FALSE(is_arithmetic, T&);

    CHECK_IS_TRAIT_CV(is_scalar, etl::nullptr_t);
    CHECK_IS_TRAIT_CV(is_scalar, etl::nullptr_t*);
    CHECK_IS_TRAIT_CV(is_scalar, bool);
    CHECK_IS_TRAIT_CV(is_scalar, bool*);
    CHECK_IS_TRAIT_CV(is_scalar, T);
    CHECK_IS_TRAIT_CV(is_scalar, T*);
    CHECK_IS_TRAIT_CV(is_scalar, T* const);
    CHECK_IS_TRAIT_CV_FALSE(is_scalar, T&);

    CHECK_IS_TRAIT_CV(is_object, T);
    CHECK_IS_TRAIT_CV(is_object, T*);
    CHECK_IS_TRAIT_CV(is_object, T* const);
    CHECK_IS_TRAIT_CV(is_object, T* const);
    CHECK_IS_TRAIT_CV_FALSE(is_object, T&);

    CHECK_IS_TRAIT_CV(is_reference, T&);
    CHECK_IS_TRAIT_CV(is_reference, T&&);
    CHECK_IS_TRAIT_CV_FALSE(is_reference, T*);
    CHECK_IS_TRAIT_CV_FALSE(is_reference, T);

    CHECK_IS_TRAIT_CV(is_lvalue_reference, T&);
    CHECK_IS_TRAIT_CV_FALSE(is_lvalue_reference, T);
    CHECK_IS_TRAIT_CV_FALSE(is_lvalue_reference, T*);
    CHECK_IS_TRAIT_CV_FALSE(is_lvalue_reference, T&&);

    CHECK_IS_TRAIT_CV(is_rvalue_reference, T&&);
    CHECK_IS_TRAIT_CV_FALSE(is_rvalue_reference, T);
    CHECK_IS_TRAIT_CV_FALSE(is_rvalue_reference, T*);
    CHECK_IS_TRAIT_CV_FALSE(is_rvalue_reference, T&);

    CHECK_IS_TRAIT_CV(is_fundamental, void);
    CHECK_IS_TRAIT_CV(is_fundamental, bool);
    CHECK_IS_TRAIT_CV(is_fundamental, etl::nullptr_t);
    CHECK_IS_TRAIT_CV(is_fundamental, T);
    CHECK_IS_TRAIT_CV_FALSE(is_fundamental, T*);
    CHECK_IS_TRAIT_CV_FALSE(is_fundamental, T&);
    CHECK_IS_TRAIT_CV_FALSE(is_fundamental, T&&);

    CHECK_IS_TRAIT_CV(is_bounded_array, T[1]);
    CHECK_IS_TRAIT_CV(is_bounded_array, T[2]);
    CHECK_IS_TRAIT_CV(is_bounded_array, T[32]);
    CHECK_IS_TRAIT_CV(is_bounded_array, T[64]);
    CHECK_IS_TRAIT_CV_FALSE(is_bounded_array, T);
    CHECK_IS_TRAIT_CV_FALSE(is_bounded_array, T*);
    CHECK_IS_TRAIT_CV_FALSE(is_bounded_array, T&);
    CHECK_IS_TRAIT_CV_FALSE(is_bounded_array, T&&);
    CHECK_IS_TRAIT_CV_FALSE(is_bounded_array, T[]);
    CHECK_IS_TRAIT_CV_FALSE(is_bounded_array, T(&)[3]);
    CHECK_IS_TRAIT_CV_FALSE(is_bounded_array, T(&)[]);
    CHECK_IS_TRAIT_CV_FALSE(is_bounded_array, T(&&)[3]);
    CHECK_IS_TRAIT_CV_FALSE(is_bounded_array, T(&&)[]);

    CHECK_IS_TRAIT_CV(is_unbounded_array, T[]);
    CHECK_IS_TRAIT_CV_FALSE(is_unbounded_array, T[64]);
    CHECK_IS_TRAIT_CV_FALSE(is_unbounded_array, T);
    CHECK_IS_TRAIT_CV_FALSE(is_unbounded_array, T*);
    CHECK_IS_TRAIT_CV_FALSE(is_unbounded_array, T&);
    CHECK_IS_TRAIT_CV_FALSE(is_unbounded_array, T&&);
    CHECK_IS_TRAIT_CV_FALSE(is_unbounded_array, T(&)[3]);
    CHECK_IS_TRAIT_CV_FALSE(is_unbounded_array, T(&)[]);
    CHECK_IS_TRAIT_CV_FALSE(is_unbounded_array, T(&&)[3]);
    CHECK_IS_TRAIT_CV_FALSE(is_unbounded_array, T(&&)[]);

    CHECK_IS_TRAIT_CV(is_array, T[]);
    CHECK_IS_TRAIT_CV(is_array, T[1]);
    CHECK_IS_TRAIT_CV(is_array, T[1][2]);
    CHECK_IS_TRAIT_CV_FALSE(is_array, etl::nullptr_t);
    CHECK_IS_TRAIT_CV_FALSE(is_array, T);

    CHECK_IS_TRAIT_CV(is_null_pointer, etl::nullptr_t);
    CHECK_IS_TRAIT_CV_FALSE(is_null_pointer, T);

    CHECK_IS_TRAIT_CV(is_pointer, T*);
    CHECK_IS_TRAIT_CV_FALSE(is_pointer, T);
    CHECK_IS_TRAIT_CV_FALSE(is_pointer, T&);
    CHECK_IS_TRAIT_CV_FALSE(is_pointer, T&&);

    CHECK_IS_TRAIT_CV(has_virtual_destructor, VirtualDtor);
    CHECK_IS_TRAIT_CV(has_virtual_destructor, Abstract);
    CHECK_IS_TRAIT_CV_FALSE(has_virtual_destructor, EmptyClass);
    CHECK_IS_TRAIT_CV_FALSE(has_virtual_destructor, T);
    CHECK_IS_TRAIT_CV_FALSE(has_virtual_destructor, T*);
    CHECK_IS_TRAIT_CV_FALSE(has_virtual_destructor, T&);
    CHECK_IS_TRAIT_CV_FALSE(has_virtual_destructor, T&&);
    CHECK_IS_TRAIT_CV_FALSE(has_virtual_destructor, etl::nullptr_t);

    CHECK_TRAIT_TYPE(remove_volatile, TV, T);
    CHECK_TRAIT_TYPE(remove_volatile, T, T);
    CHECK_TRAIT_TYPE(remove_volatile, TC, TC);
    CHECK_TRAIT_TYPE(remove_volatile, TCV, TC);

    CHECK_TRAIT_TYPE(add_volatile, T, TV);
    CHECK_TRAIT_TYPE(add_volatile, TV, TV);
    CHECK_TRAIT_TYPE(add_volatile, TC, TCV);
    CHECK_TRAIT_TYPE(add_volatile, TCV, TCV);
    CHECK_TRAIT_TYPE(add_volatile, T[42], TV[42]);
    CHECK_TRAIT_TYPE(add_volatile, TC[42], TCV[42]);
    CHECK_TRAIT_TYPE(add_volatile, TV[42], TV[42]);
    CHECK_TRAIT_TYPE(add_volatile, TCV[42], TCV[42]);
    CHECK_TRAIT_TYPE(add_volatile, T[], TV[]);
    CHECK_TRAIT_TYPE(add_volatile, TC[], TCV[]);
    CHECK_TRAIT_TYPE(add_volatile, TV[], TV[]);
    CHECK_TRAIT_TYPE(add_volatile, TCV[], TCV[]);

    CHECK_TRAIT_TYPE(remove_const, TC, T);
    CHECK_TRAIT_TYPE(remove_const, T, T);
    CHECK_TRAIT_TYPE(remove_const, TV, TV);
    CHECK_TRAIT_TYPE(remove_const, TCV, TV);
    CHECK_TRAIT_TYPE(remove_const, T&, T&);
    CHECK_TRAIT_TYPE(remove_const, TC&, TC&);
    CHECK_TRAIT_TYPE(remove_const, TV&, TV&);
    CHECK_TRAIT_TYPE(remove_const, TCV&, TCV&);
    CHECK_TRAIT_TYPE(remove_const, T&&, T&&);
    CHECK_TRAIT_TYPE(remove_const, TC&&, TC&&);
    CHECK_TRAIT_TYPE(remove_const, TV&&, TV&&);
    CHECK_TRAIT_TYPE(remove_const, TCV&&, TCV&&);
    CHECK_TRAIT_TYPE(remove_const, T[42], T[42]);
    CHECK_TRAIT_TYPE(remove_const, TC[42], T[42]);
    CHECK_TRAIT_TYPE(remove_const, TV[42], TV[42]);
    CHECK_TRAIT_TYPE(remove_const, TCV[42], TV[42]);
    CHECK_TRAIT_TYPE(remove_const, T[], T[]);
    CHECK_TRAIT_TYPE(remove_const, TC[], T[]);
    CHECK_TRAIT_TYPE(remove_const, TV[], TV[]);
    CHECK_TRAIT_TYPE(remove_const, TCV[], TV[]);

    CHECK_TRAIT_TYPE(add_const, T, TC);
    CHECK_TRAIT_TYPE(add_const, TV, TCV);
    CHECK_TRAIT_TYPE(add_const, TC, TC);
    CHECK_TRAIT_TYPE(add_const, TCV, TCV);
    CHECK_TRAIT_TYPE(add_const, T[42], TC[42]);
    CHECK_TRAIT_TYPE(add_const, TC[42], TC[42]);
    CHECK_TRAIT_TYPE(add_const, TV[42], TCV[42]);
    CHECK_TRAIT_TYPE(add_const, TCV[42], TCV[42]);
    CHECK_TRAIT_TYPE(add_const, T[], TC[]);
    CHECK_TRAIT_TYPE(add_const, TC[], TC[]);
    CHECK_TRAIT_TYPE(add_const, TV[], TCV[]);
    CHECK_TRAIT_TYPE(add_const, TCV[], TCV[]);

    CHECK_TRAIT_TYPE(remove_cv, TC, T);
    CHECK_TRAIT_TYPE(remove_cv, T, T);
    CHECK_TRAIT_TYPE(remove_cv, TV, T);
    CHECK_TRAIT_TYPE(remove_cv, TCV, T);
    CHECK_TRAIT_TYPE(remove_cv, T[42], T[42]);
    CHECK_TRAIT_TYPE(remove_cv, TC[42], T[42]);
    CHECK_TRAIT_TYPE(remove_cv, TV[42], T[42]);
    CHECK_TRAIT_TYPE(remove_cv, TCV[42], T[42]);
    CHECK_TRAIT_TYPE(remove_cv, T[], T[]);
    CHECK_TRAIT_TYPE(remove_cv, TC[], T[]);
    CHECK_TRAIT_TYPE(remove_cv, TV[], T[]);
    CHECK_TRAIT_TYPE(remove_cv, TCV[], T[]);
    CHECK_TRAIT_TYPE(remove_cv, T&, T&);
    CHECK_TRAIT_TYPE(remove_cv, TC&, TC&);
    CHECK_TRAIT_TYPE(remove_cv, TV&, TV&);
    CHECK_TRAIT_TYPE(remove_cv, TCV&, TCV&);
    CHECK_TRAIT_TYPE(remove_cv, T&&, T&&);
    CHECK_TRAIT_TYPE(remove_cv, TC&&, TC&&);
    CHECK_TRAIT_TYPE(remove_cv, TV&&, TV&&);
    CHECK_TRAIT_TYPE(remove_cv, TCV&&, TCV&&);

    CHECK_TRAIT_TYPE(add_cv, T, TCV);
    CHECK_TRAIT_TYPE(add_cv, TV, TCV);
    CHECK_TRAIT_TYPE(add_cv, TC, TCV);
    CHECK_TRAIT_TYPE(add_cv, TCV, TCV);
    CHECK_TRAIT_TYPE(add_cv, T[42], TCV[42]);
    CHECK_TRAIT_TYPE(add_cv, TC[42], TCV[42]);
    CHECK_TRAIT_TYPE(add_cv, TV[42], TCV[42]);
    CHECK_TRAIT_TYPE(add_cv, TCV[42], TCV[42]);
    CHECK_TRAIT_TYPE(add_cv, T[], TCV[]);
    CHECK_TRAIT_TYPE(add_cv, TC[], TCV[]);
    CHECK_TRAIT_TYPE(add_cv, TV[], TCV[]);
    CHECK_TRAIT_TYPE(add_cv, TCV[], TCV[]);

    CHECK_TRAIT_TYPE(remove_cvref, T, T);
    CHECK_TRAIT_TYPE(remove_cvref, TC, T);
    CHECK_TRAIT_TYPE(remove_cvref, TV, T);
    CHECK_TRAIT_TYPE(remove_cvref, TCV, T);
    CHECK_TRAIT_TYPE(remove_cvref, T[42], T[42]);
    CHECK_TRAIT_TYPE(remove_cvref, TC[42], T[42]);
    CHECK_TRAIT_TYPE(remove_cvref, TV[42], T[42]);
    CHECK_TRAIT_TYPE(remove_cvref, TCV[42], T[42]);
    CHECK_TRAIT_TYPE(remove_cvref, T[], T[]);
    CHECK_TRAIT_TYPE(remove_cvref, TC[], T[]);
    CHECK_TRAIT_TYPE(remove_cvref, TV[], T[]);
    CHECK_TRAIT_TYPE(remove_cvref, TCV[], T[]);
    CHECK_TRAIT_TYPE(remove_cvref, T&, T);
    CHECK_TRAIT_TYPE(remove_cvref, TC&, T);
    CHECK_TRAIT_TYPE(remove_cvref, TV&, T);
    CHECK_TRAIT_TYPE(remove_cvref, TCV&, T);
    CHECK_TRAIT_TYPE(remove_cvref, T&&, T);
    CHECK_TRAIT_TYPE(remove_cvref, TC&&, T);
    CHECK_TRAIT_TYPE(remove_cvref, TV&&, T);
    CHECK_TRAIT_TYPE(remove_cvref, TCV&&, T);

    CHECK_TRAIT_TYPE(add_pointer, T, T*);
    CHECK_TRAIT_TYPE(add_pointer, TV, TV*);
    CHECK_TRAIT_TYPE(add_pointer, TC, TC*);
    CHECK_TRAIT_TYPE(add_pointer, TCV, TCV*);
    CHECK_TRAIT_TYPE(remove_pointer, T*, T);
    CHECK_TRAIT_TYPE(remove_pointer, TC*, TC);
    CHECK_TRAIT_TYPE(remove_pointer, TV*, TV);
    CHECK_TRAIT_TYPE(remove_pointer, TCV*, TCV);

    CHECK_TRAIT_TYPE(remove_reference, T, T);
    CHECK_TRAIT_TYPE(remove_reference, T*, T*);
    CHECK_TRAIT_TYPE(remove_reference, T&, T);
    CHECK_TRAIT_TYPE(remove_reference, TC&, TC);
    CHECK_TRAIT_TYPE(remove_reference, TV&, TV);
    CHECK_TRAIT_TYPE(remove_reference, TCV&, TCV);
    CHECK_TRAIT_TYPE(remove_reference, T&&, T);
    CHECK_TRAIT_TYPE(remove_reference, TC&&, TC);
    CHECK_TRAIT_TYPE(remove_reference, TV&&, TV);
    CHECK_TRAIT_TYPE(remove_reference, TCV&&, TCV);

    CHECK_TRAIT_TYPE(add_lvalue_reference, T, T&);
    CHECK_TRAIT_TYPE(add_lvalue_reference, TC, TC&);
    CHECK_TRAIT_TYPE(add_lvalue_reference, TV, TV&);
    CHECK_TRAIT_TYPE(add_lvalue_reference, TCV, TCV&);
    CHECK_TRAIT_TYPE(add_lvalue_reference, void, void);
    CHECK_TRAIT_TYPE(add_lvalue_reference, void const, void const);
    CHECK_TRAIT_TYPE(add_lvalue_reference, void volatile, void volatile);
    CHECK_TRAIT_TYPE(add_lvalue_reference, void const volatile, void const volatile);

    CHECK_TRAIT_TYPE(add_rvalue_reference, T, T&&);
    CHECK_TRAIT_TYPE(add_rvalue_reference, TC, TC&&);
    CHECK_TRAIT_TYPE(add_rvalue_reference, TV, TV&&);
    CHECK_TRAIT_TYPE(add_rvalue_reference, TCV, TCV&&);

    CHECK_IS_TRAIT_CV(is_trivial, T*);
    CHECK_IS_TRAIT_CV_FALSE(is_trivial, T&);

    CHECK_IS_TRAIT(is_swappable, T);
    CHECK_IS_TRAIT_CV(is_swappable, T*);
    CHECK_IS_TRAIT_CV(is_swappable, void*);

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

    CHECK(sizeof(etl::aligned_union_t<0, char>) == 1);
    CHECK(sizeof(etl::aligned_union_t<2, char>) == 2);
    CHECK(sizeof(etl::aligned_union_t<2, char[3]>) == 3);
    CHECK(sizeof(etl::aligned_union_t<3, char[4]>) == 4);

#if not defined(__AVR__)
    CHECK(sizeof(etl::aligned_union_t<1, char, T, double>) == 8);
    CHECK(sizeof(etl::aligned_union_t<12, char, T, double>) == 16);
#endif

    CHECK(etl::is_specialized_v<test_is_specialized, Foo<float>>);
    CHECK_FALSE(etl::is_specialized_v<test_is_specialized, T>);
    CHECK_FALSE(etl::is_specialized_v<test_is_specialized, double>);

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
