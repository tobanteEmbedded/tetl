/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/type_traits.hpp"

#include "etl/version.hpp"

#include "testing.hpp"
#include "types.hpp"

using etl::is_same;
using etl::is_same_v;

using etl::make_signed_t;
static_assert(is_same_v<make_signed_t<etl::int8_t>, etl::int8_t>);
static_assert(is_same_v<make_signed_t<etl::int16_t>, etl::int16_t>);
static_assert(is_same_v<make_signed_t<etl::int32_t>, etl::int32_t>);
static_assert(is_same_v<make_signed_t<etl::int64_t>, etl::int64_t>);

static_assert(is_same_v<make_signed_t<etl::uint8_t>, etl::int8_t>);
static_assert(is_same_v<make_signed_t<etl::uint16_t>, etl::int16_t>);
static_assert(is_same_v<make_signed_t<etl::uint32_t>, etl::int32_t>);
static_assert(is_same_v<make_signed_t<etl::uint64_t>, etl::int64_t>);

static_assert(is_same_v<make_signed_t<signed char>, signed char>);
static_assert(is_same_v<make_signed_t<short>, short>);
static_assert(is_same_v<make_signed_t<int>, int>);
static_assert(is_same_v<make_signed_t<long>, long>);
static_assert(is_same_v<make_signed_t<long long>, long long>);

static_assert(is_same_v<make_signed_t<unsigned char>, signed char>);
static_assert(is_same_v<make_signed_t<unsigned short>, short>);
static_assert(is_same_v<make_signed_t<unsigned int>, int>);
static_assert(is_same_v<make_signed_t<unsigned long>, long>);
static_assert(is_same_v<make_signed_t<unsigned long long>, long long>);

// clang-format off
using etl::make_unsigned_t;
static_assert(is_same_v<make_unsigned_t<etl::int8_t>, etl::uint8_t>);
static_assert(is_same_v<make_unsigned_t<etl::int16_t>, etl::uint16_t>);
static_assert(is_same_v<make_unsigned_t<etl::int32_t>, etl::uint32_t>);
static_assert(is_same_v<make_unsigned_t<etl::int64_t>, etl::uint64_t>);

static_assert(is_same_v<make_unsigned_t<etl::uint8_t>, etl::uint8_t>);
static_assert(is_same_v<make_unsigned_t<etl::uint16_t>, etl::uint16_t>);
static_assert(is_same_v<make_unsigned_t<etl::uint32_t>, etl::uint32_t>);
static_assert(is_same_v<make_unsigned_t<etl::uint64_t>, etl::uint64_t>);

static_assert(is_same_v<make_unsigned_t<signed char>, unsigned char>);
static_assert(is_same_v<make_unsigned_t<short>, unsigned short>);
static_assert(is_same_v<make_unsigned_t<int>, unsigned int>);
static_assert(is_same_v<make_unsigned_t<long>, unsigned long>);
static_assert(is_same_v<make_unsigned_t<long long>, unsigned long long>);

static_assert(is_same_v<make_unsigned_t<unsigned char>, unsigned char>);
static_assert(is_same_v<make_unsigned_t<unsigned short>, unsigned short>);
static_assert(is_same_v<make_unsigned_t<unsigned int>, unsigned int>);
static_assert(is_same_v<make_unsigned_t<unsigned long>, unsigned long>);
static_assert(is_same_v<make_unsigned_t<unsigned long long>, unsigned long long>);
// clang-format on

namespace {
template <typename T>
struct Foo {
    T i {};
};

struct IDS {
};
template <typename T>
struct test_is_specialized;

template <>
struct test_is_specialized<Foo<float>> {
};

struct not_specialized {
};

template <typename T>
constexpr auto test_identity() -> bool
{
    using etl::is_same_v;
    using etl::type_identity;
    using etl::type_identity_t;

    assert((is_same_v<T, typename type_identity<T>::type>));
    assert((is_same_v<T, type_identity_t<T>>));

    // clang-format off
    if constexpr (!etl::is_function_v<T>) {
        assert((is_same_v<T const, typename type_identity<T const>::type>));
        assert((is_same_v<T volatile, typename type_identity<T volatile>::type>));
        assert((is_same_v<T const volatile, typename type_identity<T const volatile>::type>));

        assert((is_same_v<T const, type_identity_t<T const>>));
        assert((is_same_v<T volatile, type_identity_t<T volatile>>));
        assert((is_same_v<T const volatile, type_identity_t<T const volatile>>));
    }

    if constexpr (!etl::is_void_v<T>) {
        assert((is_same_v<T&, typename type_identity<T&>::type>));
        assert((is_same_v<T&&, typename type_identity<T&&>::type>));

        assert((is_same_v<T&, type_identity_t<T&>>));
        assert((is_same_v<T&&, type_identity_t<T&&>>));
    }

    if constexpr (!etl::is_void_v<T> && !etl::is_function_v<T>) {
        assert((is_same_v<T const&, typename type_identity<T const&>::type>));
        assert((is_same_v<T volatile&, typename type_identity<T volatile&>::type>));
        assert((is_same_v<T const volatile&, typename type_identity<T const volatile&>::type>));
        assert((is_same_v<T const&&, typename type_identity<T const&&>::type>));
        assert((is_same_v<T volatile&&, typename type_identity<T volatile&&>::type>));
        assert((is_same_v<T const volatile&&, typename type_identity<T const volatile&&>::type>));

        assert((is_same_v<T const&, type_identity_t<T const&>>));
        assert((is_same_v<T volatile&, type_identity_t<T volatile&>>));
        assert((is_same_v<T const volatile&, type_identity_t<T const volatile&>>));
        assert((is_same_v<T const&&, type_identity_t<T const&&>>));
        assert((is_same_v<T volatile&&, type_identity_t<T volatile&&>>));
        assert((is_same_v<T const volatile&&, type_identity_t<T const volatile&&>>));
    }

    // clang-format on
    return true;
}
} // namespace

template <typename T>
constexpr auto test() -> bool
{

    using TC  = T const;
    using TV  = T volatile;
    using TCV = T const volatile;

    using etl::conjunction_v;
    assert((conjunction_v<is_same<Foo<T>, Foo<T>>, is_same<short, short>>));
    assert((conjunction_v<is_same<short, short>, is_same<float, float>>));
    assert((conjunction_v<is_same<Foo<T>, Foo<T>>, is_same<double, double>>));
    assert(!(conjunction_v<is_same<float, Foo<T>>, is_same<char, char>>));
    assert(!(conjunction_v<is_same<Foo<T>, short>, is_same<char, char>>));
    assert(!(conjunction_v<is_same<Foo<T>, Foo<T>>, is_same<char, float>>));

    using etl::disjunction_v;
    assert((disjunction_v<is_same<Foo<T>, Foo<T>>, is_same<short, short>>));
    assert((disjunction_v<is_same<short, short>, is_same<float, float>>));
    assert((disjunction_v<is_same<Foo<T>, Foo<T>>, is_same<double, double>>));
    assert((disjunction_v<is_same<float, Foo<T>>, is_same<short, short>>));
    assert((disjunction_v<is_same<Foo<T>, short>, is_same<float, float>>));
    assert((disjunction_v<is_same<Foo<T>, Foo<T>>, is_same<double, float>>));
    assert(!(disjunction_v<is_same<char, Foo<T>>, is_same<short, char>>));
    assert(!(disjunction_v<is_same<Foo<T>, short>, is_same<float, Foo<T>>>));
    assert(!(disjunction_v<is_same<bool, Foo<T>>, is_same<char, float>>));

    assert((etl::negation_v<etl::is_same<short, float>>));
    assert((etl::negation_v<etl::is_same<bool, float>>));
    assert((etl::negation_v<etl::is_same<Foo<T>, float>>));
    assert(!(etl::negation_v<etl::is_same<Foo<T>, Foo<T>>>));
    assert(!(etl::negation_v<etl::is_same<bool, bool>>));
    assert(!(etl::negation_v<etl::is_same<float, float>>));

    assert((etl::rank<T>::value == 0));
    assert((etl::rank_v<T> == 0));
    assert((etl::rank<T[5]>::value == 1));
    assert((etl::rank<T[5][5]>::value == 2));
    assert((etl::rank<T[][5][5]>::value == 3));

    using etl::remove_extent_t;
    assert((is_same_v<remove_extent_t<T>, T>));
    assert((is_same_v<remove_extent_t<T*>, T*>));
    assert((is_same_v<remove_extent_t<T&>, T&>));
    assert((is_same_v<remove_extent_t<T const>, T const>));
    assert((is_same_v<remove_extent_t<T[]>, T>));
    assert((is_same_v<remove_extent_t<T[1]>, T>));
    assert((is_same_v<remove_extent_t<T[16]>, T>));
    assert((is_same_v<remove_extent_t<T[1][2]>, T[2]>));
    assert((is_same_v<remove_extent_t<T[1][2][3]>, T[2][3]>));

    using etl::remove_all_extents_t;
    assert((is_same_v<remove_all_extents_t<T>, T>));
    assert((is_same_v<remove_all_extents_t<T*>, T*>));
    assert((is_same_v<remove_all_extents_t<T&>, T&>));
    assert((is_same_v<remove_all_extents_t<T const>, T const>));
    assert((is_same_v<remove_all_extents_t<T[]>, T>));
    assert((is_same_v<remove_all_extents_t<T[1]>, T>));
    assert((is_same_v<remove_all_extents_t<T[16]>, T>));
    assert((is_same_v<remove_all_extents_t<T[1][2]>, T>));
    assert((is_same_v<remove_all_extents_t<T[1][2][3]>, T>));

    // TODO: Broken on MSVC
    //  assert((is_same_v<decay_t<T(T)>, T (*)(T)>));
    TEST_TRAIT_TYPE(decay, T, T);
    TEST_TRAIT_TYPE(decay, T&, T);
    TEST_TRAIT_TYPE(decay, T&&, T);
    TEST_TRAIT_TYPE(decay, T const&, T);
    TEST_TRAIT_TYPE(decay, T[2], T*);

    using etl::common_type_t;
    assert((is_same_v<common_type_t<T>, T>));
    assert((is_same_v<common_type_t<T, T>, T>));
    assert((is_same_v<common_type_t<T, T const>, T>));
    assert((is_same_v<common_type_t<T, T volatile>, T>));
    assert((is_same_v<common_type_t<T, T const volatile>, T>));
    assert((is_same_v<common_type_t<T, double>, double>));

    if constexpr (etl::is_integral_v<T>) {
        auto const constant = etl::integral_constant<T, T { 0 }> {};
        assert(decltype(constant)::value == T { 0 });
        assert(constant() == T { 0 });
        assert(static_cast<T>(constant) == T { 0 });
        assert((etl::is_same_v<T, typename decltype(constant)::value_type>));
    }

    // false
    {
        auto const constant = etl::bool_constant<false> {};
        assert((decltype(constant)::value == false));
        assert((constant() == false));
        assert((static_cast<bool>(constant) == false));
        assert((etl::is_same_v<bool, decltype(constant)::value_type>));
    }

    // true
    {
        auto const constant = etl::bool_constant<true> {};
        assert((decltype(constant)::value == true));
        assert((constant() == true));
        assert((static_cast<bool>(constant) == true));
        assert((etl::is_same_v<bool, decltype(constant)::value_type>));
    }

    // true_type
    {
        assert((etl::is_same_v<bool, etl::true_type::value_type>));
        assert((etl::true_type::value == true));
    }

    // false_type
    {
        assert((etl::is_same_v<bool, etl::false_type::value_type>));
        assert((etl::false_type::value == false));
    }

    assert((etl::is_same_v<struct S, T> == false));
    assert((etl::is_same_v<struct S, T> == false));
    assert((etl::is_same<T, T>::value == true));

    assert((etl::is_void<T>::value == false));
    assert((etl::is_void_v<T> == false));
    assert((etl::is_void<void>::value == true));
    assert((etl::is_void_v<void>));

    assert((etl::is_const<TC>::value));
    assert((etl::is_const_v<TC>));

    assert(!(etl::is_const<T>::value));
    assert(!(etl::is_const_v<T>));
    assert(!(etl::is_const<TV>::value));
    assert(!(etl::is_const_v<TV>));

    assert((etl::is_volatile_v<TV>));
    assert(!(etl::is_volatile_v<T>));
    assert(!(etl::is_volatile_v<TC>));

    using etl::is_convertible_v;

    assert((is_convertible_v<void, void>));

    // TODO: [tobi] The assertions below trigger an internal compiler error on
    // MSVC
#if not defined(TETL_MSVC)

    assert(!(is_convertible_v<int, void>));
    assert(!(is_convertible_v<int, const void>));

    assert((is_convertible_v<void, void const>));
    assert((is_convertible_v<void const, void>));
    assert((is_convertible_v<void const, void const>));

    #if TETL_CPP_STANDARD < 20
    assert(!(is_convertible_v<int, volatile void>));
    assert(!(is_convertible_v<int, const volatile void>));
    assert((is_convertible_v<void, void volatile>));
    assert((is_convertible_v<void, void const volatile>));
    assert((is_convertible_v<void const, void volatile>));
    assert((is_convertible_v<void const, void const volatile>));
    assert((is_convertible_v<void volatile, void volatile>));
    assert((is_convertible_v<void volatile, void const volatile>));
    assert((is_convertible_v<void volatile, void>));
    assert((is_convertible_v<void volatile, void const>));
    assert((is_convertible_v<void const volatile, void>));
    assert((is_convertible_v<void const volatile, void const>));
    assert((is_convertible_v<void const volatile, void volatile>));
    assert((is_convertible_v<void const volatile, void const volatile>));
    #endif

#endif

    assert(etl::is_lvalue_reference_v<T&>);
    assert(etl::is_lvalue_reference_v<T const&>);
    assert(!etl::is_lvalue_reference<T>::value);
    assert(!etl::is_lvalue_reference<T const>::value);
    assert(!etl::is_lvalue_reference<T*>::value);
    assert(!etl::is_lvalue_reference<T const*>::value);
    assert(!etl::is_lvalue_reference<T&&>::value);

    assert(etl::is_rvalue_reference<T&&>::value);

    assert(!(etl::is_rvalue_reference_v<T&>));
    assert(!(etl::is_rvalue_reference_v<TC&>));
    assert(!(etl::is_rvalue_reference<T>::value));
    assert(!(etl::is_rvalue_reference<TC>::value));
    assert(!(etl::is_rvalue_reference<T*>::value));
    assert(!(etl::is_rvalue_reference<TC*>::value));

    assert(etl::is_arithmetic<bool>::value);
    assert(etl::is_arithmetic<T>::value);
    assert(etl::is_arithmetic<TC>::value);
    assert(etl::is_arithmetic<TV>::value);
    assert(!(etl::is_arithmetic<T&>::value));
    assert(!(etl::is_arithmetic<TC&>::value));
    assert(!(etl::is_arithmetic<T*>::value));
    assert(!(etl::is_arithmetic<TC*>::value));
    assert(!(etl::is_arithmetic<TC* const>::value));

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
    TEST_IS_TRAIT_CV(is_reference, T &&);
    TEST_IS_TRAIT_CV_FALSE(is_reference, T*);
    TEST_IS_TRAIT_CV_FALSE(is_reference, T);

    TEST_IS_TRAIT_CV(is_fundamental, void);
    TEST_IS_TRAIT_CV(is_fundamental, bool);
    TEST_IS_TRAIT_CV(is_fundamental, etl::nullptr_t);
    TEST_IS_TRAIT_CV(is_fundamental, T);
    TEST_IS_TRAIT_CV_FALSE(is_fundamental, T*);
    TEST_IS_TRAIT_CV_FALSE(is_fundamental, T&);
    TEST_IS_TRAIT_CV_FALSE(is_fundamental, T &&);

    TEST_IS_TRAIT_CV(is_bounded_array, T[1]);
    TEST_IS_TRAIT_CV(is_bounded_array, T[2]);
    TEST_IS_TRAIT_CV(is_bounded_array, T[32]);
    TEST_IS_TRAIT_CV(is_bounded_array, T[64]);
    TEST_IS_TRAIT_CV_FALSE(is_bounded_array, T);
    TEST_IS_TRAIT_CV_FALSE(is_bounded_array, T*);
    TEST_IS_TRAIT_CV_FALSE(is_bounded_array, T&);
    TEST_IS_TRAIT_CV_FALSE(is_bounded_array, T &&);
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
    TEST_IS_TRAIT_CV_FALSE(is_unbounded_array, T &&);
    TEST_IS_TRAIT_CV_FALSE(is_unbounded_array, T(&)[3]);
    TEST_IS_TRAIT_CV_FALSE(is_unbounded_array, T(&)[]);
    TEST_IS_TRAIT_CV_FALSE(is_unbounded_array, T(&&)[3]);
    TEST_IS_TRAIT_CV_FALSE(is_unbounded_array, T(&&)[]);

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
    TEST_TRAIT_TYPE(remove_const, T&&, T &&);
    TEST_TRAIT_TYPE(remove_const, TC&&, TC &&);
    TEST_TRAIT_TYPE(remove_const, TV&&, TV &&);
    TEST_TRAIT_TYPE(remove_const, TCV&&, TCV &&);
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

    using etl::remove_cv_t;
    assert((is_same_v<remove_cv_t<TC>, T>));
    assert((is_same_v<remove_cv_t<TV>, T>));
    assert((is_same_v<remove_cv_t<TCV>, T>));

    using etl::add_cv_t;
    assert((is_same_v<add_cv_t<T>, T const volatile>));
    assert((is_same_v<add_cv_t<T const>, T const volatile>));
    assert((is_same_v<add_cv_t<T volatile>, T const volatile>));
    assert((is_same_v<add_cv_t<T const volatile>, T const volatile>));

    using etl::remove_cvref_t;
    assert((is_same_v<remove_cvref_t<T>, T>));
    assert((is_same_v<remove_cvref_t<T&>, T>));
    assert((is_same_v<remove_cvref_t<T&&>, T>));
    assert((is_same_v<remove_cvref_t<TC&>, T>));

    using etl::add_pointer_t;
    assert((is_same_v<add_pointer_t<T>, T*>));
    assert((is_same_v<add_pointer_t<TC>, TC*>));
    assert((is_same_v<add_pointer_t<TV>, TV*>));
    assert((is_same_v<add_pointer_t<TCV>, TCV*>));

    using etl::remove_pointer_t;
    assert((is_same_v<remove_pointer_t<T*>, T>));
    assert((is_same_v<remove_pointer_t<TC*>, TC>));
    assert((is_same_v<remove_pointer_t<TV*>, TV>));
    assert((is_same_v<remove_pointer_t<TCV*>, TCV>));

    using etl::remove_reference_t;
    assert((is_same_v<T, T>));
    assert(!(is_same_v<T, T&>));
    assert(!(is_same_v<T, T&&>));

    assert((is_same_v<T, remove_reference_t<T>>));
    assert((is_same_v<T, remove_reference_t<T&>>));
    assert((is_same_v<T, remove_reference_t<T&&>>));

    assert((is_same_v<TC, remove_reference_t<TC>>));
    assert((is_same_v<TC, remove_reference_t<TC&>>));
    assert((is_same_v<TC, remove_reference_t<TC&&>>));

    assert((is_same_v<TV, remove_reference_t<TV>>));
    assert((is_same_v<TV, remove_reference_t<TV&>>));
    assert((is_same_v<TV, remove_reference_t<TV&&>>));

    assert((is_same_v<TCV, remove_reference_t<TCV>>));
    assert((is_same_v<TCV, remove_reference_t<TCV&>>));
    assert((is_same_v<TCV, remove_reference_t<TCV&&>>));

    using etl::add_lvalue_reference_t;

    assert((is_same_v<add_lvalue_reference_t<T>, T&>));
    assert((is_same_v<add_lvalue_reference_t<TC>, TC&>));
    assert((is_same_v<add_lvalue_reference_t<TV>, TV&>));
    assert((is_same_v<add_lvalue_reference_t<TCV>, TCV&>));

    // clang-format off
    assert((is_same_v<void, add_lvalue_reference_t<void>>));
    assert((is_same_v<void const, add_lvalue_reference_t<void const>>));
    assert((is_same_v<void volatile, add_lvalue_reference_t<void volatile>>));
    assert((is_same_v<void const volatile, add_lvalue_reference_t<void const volatile>>));
    // clang-format on

    using etl::add_rvalue_reference_t;
    assert((is_same_v<add_rvalue_reference_t<T>, T&&>));
    assert((is_same_v<add_rvalue_reference_t<TC>, TC&&>));
    assert((is_same_v<add_rvalue_reference_t<TV>, TV&&>));
    assert((is_same_v<add_rvalue_reference_t<TCV>, TCV&&>));

    assert(etl::is_trivial_v<T*>);
    assert(etl::is_trivial_v<T const*>);
    assert(etl::is_trivial_v<T volatile*>);
    assert(etl::is_trivial_v<T const volatile*>);

    assert(!(etl::is_trivial_v<T&>));
    assert(!(etl::is_trivial_v<T const&>));
    assert(!(etl::is_trivial_v<T volatile&>));
    assert(!(etl::is_trivial_v<T const volatile&>));

    using etl::is_swappable_v;
    assert((is_swappable_v<T>));
    assert((is_swappable_v<T*>));
    assert((is_swappable_v<T const*>));
    assert((is_swappable_v<T volatile*>));
    assert((is_swappable_v<T const volatile*>));
    assert((is_swappable_v<void*>));
    assert((is_swappable_v<void const*>));
    assert((is_swappable_v<void volatile*>));
    assert((is_swappable_v<void const volatile*>));

    // clang-format off
    assert((test_identity<void>()));
    assert((test_identity<T>()));
    assert((test_identity<T*>()));
    assert((test_identity<T const*>()));
    assert((test_identity<T volatile*>()));
    assert((test_identity<T const volatile*>()));
    assert((test_identity<T[3]>()));
    assert((test_identity<T[]>()));
    assert((test_identity<T(T)>()));
    assert((test_identity<T&(T)>()));
    assert((test_identity<T const&(T)>()));
    assert((test_identity<T volatile&(T)>()));
    assert((test_identity<T const volatile&(T)>()));
    assert((test_identity<T(T&)>()));
    assert((test_identity<T(T const&)>()));
    assert((test_identity<T(T volatile&)>()));
    assert((test_identity<T(T const volatile&)>()));
    assert((test_identity<T IDS::*>()));
    assert((test_identity<T const IDS::*>()));
    assert((test_identity<T volatile IDS::*>()));
    assert((test_identity<T const volatile IDS::*>()));
    assert((test_identity<T (IDS::*)(T)>()));
    assert((test_identity<T (IDS::*)(T&)>()));
    assert((test_identity<T (IDS::*)(T const&) const>()));
    assert((test_identity<T (IDS::*)(T volatile&) volatile>()));
    assert((test_identity<T (IDS::*)(T const volatile&) const volatile>()));
    assert((test_identity<T (IDS::*)(T)&>()));
    assert((test_identity<T (IDS::*)(T) const&>()));
    assert((test_identity<T (IDS::*)(T) &&>()));
    assert((test_identity<T (IDS::*)(T) const&&>()));
    assert((test_identity<T& (IDS::*)(T)>()));
    assert((test_identity<T const& (IDS::*)(T)>()));
    assert((test_identity<T volatile& (IDS::*)(T)>()));
    assert((test_identity<T const volatile& (IDS::*)(T)>()));
    // clang-format on

    assert((sizeof(etl::aligned_union_t<0, char>) == 1));
    assert((sizeof(etl::aligned_union_t<2, char>) == 2));
    assert((sizeof(etl::aligned_union_t<2, char[3]>) == 3));
    assert((sizeof(etl::aligned_union_t<3, char[4]>) == 4));
    assert((sizeof(etl::aligned_union_t<1, char, T, double>) == 8));
    assert((sizeof(etl::aligned_union_t<12, char, T, double>) == 16));

    using etl::type_pack_element_t;
    assert((is_same_v<type_pack_element_t<0, T>, T>));
    assert((is_same_v<type_pack_element_t<1, T, float>, float>));
    assert((is_same_v<type_pack_element_t<2, T, char, short>, short>));

    assert((etl::is_specialized_v<test_is_specialized, Foo<float>>));
    assert(!(etl::is_specialized_v<test_is_specialized, T>));
    assert(!(etl::is_specialized_v<test_is_specialized, double>));

    return true;
}

constexpr auto test_all() -> bool
{
    assert(test<char>());
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
    // assert(test<long double>());

    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}