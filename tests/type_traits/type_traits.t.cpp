/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/type_traits.hpp"

#include "etl/version.hpp"

#include "testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    using TC  = T const;
    using TV  = T volatile;
    using TCV = T const volatile;

    {
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

    assert(!(is_convertible_v<int, void>));
    assert(!(is_convertible_v<int, const void>));

    assert((is_convertible_v<void, void const>));
    assert((is_convertible_v<void const, void>));
    assert((is_convertible_v<void const, void const>));

#if TETL_CPP_STANDARD == 17
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

    assert(etl::is_rvalue_reference<T&&>::value);

    assert(!(etl::is_rvalue_reference_v<T&>));
    assert(!(etl::is_rvalue_reference_v<TC&>));
    assert(!(etl::is_rvalue_reference<T>::value));
    assert(!(etl::is_rvalue_reference<TC>::value));
    assert(!(etl::is_rvalue_reference<T*>::value));
    assert(!(etl::is_rvalue_reference<TC*>::value));

    assert(etl::is_class_v<T> == false);

    assert(etl::is_enum_v<T> == false);
    assert(etl::is_enum_v<TC> == false);
    assert(etl::is_enum_v<TV> == false);
    assert(etl::is_enum_v<T*> == false);
    assert(etl::is_enum_v<TC*> == false);
    assert(etl::is_enum_v<TC* const> == false);
    assert(etl::is_enum_v<T&> == false);
    assert(etl::is_enum_v<TC&> == false);

    assert(etl::is_union_v<T> == false);
    assert(etl::is_union_v<TC> == false);
    assert(etl::is_union_v<TV> == false);
    assert(etl::is_union_v<T*> == false);
    assert(etl::is_union_v<TC*> == false);
    assert(etl::is_union_v<TC* const> == false);
    assert(etl::is_union_v<T&> == false);
    assert(etl::is_union_v<TC&> == false);

    assert(etl::is_arithmetic<bool>::value);
    assert(etl::is_arithmetic<T>::value);
    assert(etl::is_arithmetic<TC>::value);
    assert(etl::is_arithmetic<TV>::value);
    assert(!(etl::is_arithmetic<T&>::value));
    assert(!(etl::is_arithmetic<TC&>::value));
    assert(!(etl::is_arithmetic<T*>::value));
    assert(!(etl::is_arithmetic<TC*>::value));
    assert(!(etl::is_arithmetic<TC* const>::value));

    assert(etl::is_scalar_v<etl::nullptr_t>);
    assert(etl::is_scalar_v<etl::nullptr_t const>);
    assert(etl::is_scalar_v<etl::nullptr_t volatile>);
    assert(etl::is_scalar_v<etl::nullptr_t*>);
    assert(etl::is_scalar_v<etl::nullptr_t const*>);
    assert(etl::is_scalar_v<etl::nullptr_t const* const>);
    assert(etl::is_scalar_v<bool>);
    assert(etl::is_scalar_v<bool const>);
    assert(etl::is_scalar_v<bool volatile>);
    assert(etl::is_scalar_v<bool*>);
    assert(etl::is_scalar_v<bool const*>);
    assert(etl::is_scalar_v<bool const* const>);
    assert(etl::is_scalar_v<T>);
    assert(etl::is_scalar_v<TC>);
    assert(etl::is_scalar_v<TV>);
    assert(etl::is_scalar_v<T*>);
    assert(etl::is_scalar_v<TC*>);
    assert(etl::is_scalar_v<TC* const>);

    assert(!(etl::is_scalar_v<T&>));
    assert(!(etl::is_scalar_v<TC&>));

    assert(etl::is_object_v<T>);
    assert(etl::is_object_v<TC>);
    assert(etl::is_object_v<TV>);
    assert(etl::is_object_v<T*>);
    assert(etl::is_object_v<TC*>);
    assert(etl::is_object_v<TC* const>);

    assert(!(etl::is_object_v<T&>));
    assert(!(etl::is_object_v<TC&>));

    assert(!(etl::is_compound<T>::value));
    assert(!(etl::is_compound_v<T>));
    assert(etl::is_compound_v<T*>);
    assert(etl::is_compound_v<T&>);

    assert(!(etl::is_reference<T>::value));
    assert(!(etl::is_reference_v<T>));

    assert((etl::is_reference_v<T&&>));
    assert((etl::is_reference_v<T&>));
    assert((etl::is_reference_v<TC&&>));
    assert((etl::is_reference_v<TC&>));
    assert((etl::is_reference_v<TV&&>));
    assert((etl::is_reference_v<TV&>));
    assert((etl::is_reference_v<TV const&&>));
    assert((etl::is_reference_v<TV const&>));

    assert((etl::is_fundamental_v<void>));
    assert((etl::is_fundamental_v<etl::nullptr_t>));
    assert((etl::is_fundamental_v<T>));
    assert((etl::is_fundamental_v<TC>));
    assert((etl::is_fundamental_v<TV>));

    assert(!(etl::is_fundamental_v<T&>));
    assert(!(etl::is_fundamental_v<TC&>));
    assert(!(etl::is_fundamental_v<T*>));
    assert(!(etl::is_fundamental_v<TC*>));
    assert(!(etl::is_fundamental_v<TC* const>));

    assert((etl::is_bounded_array_v<T[1]>));
    assert((etl::is_bounded_array_v<T[2]>));
    assert((etl::is_bounded_array_v<T[64]>));

    assert(!(etl::is_bounded_array_v<T>));
    assert(!(etl::is_bounded_array_v<T>));
    assert(!(etl::is_bounded_array_v<T*>));
    assert(!(etl::is_bounded_array_v<T[]>));

    // lvalue/rvalue references aren't bounded/unbounded arrays.
    assert(!(etl::is_bounded_array_v<T(&)[3]>));
    assert(!(etl::is_bounded_array_v<T(&)[]>));
    assert(!(etl::is_bounded_array_v<T(&&)[3]>));
    assert(!(etl::is_bounded_array_v<T(&&)[]>));

    assert((etl::is_unbounded_array_v<T[]>));

    assert(!(etl::is_unbounded_array_v<T>));
    assert(!(etl::is_unbounded_array_v<T*>));
    assert(!(etl::is_unbounded_array_v<T&>));
    assert(!(etl::is_unbounded_array_v<T[1]>));
    assert(!(etl::is_unbounded_array_v<T[2]>));
    assert(!(etl::is_unbounded_array_v<T[64]>));

    // lvalue/rvalue references aren't bounded/unbounded arrays.
    assert(!(etl::is_unbounded_array_v<T(&)[3]>));
    assert(!(etl::is_unbounded_array_v<T(&)[]>));
    assert(!(etl::is_unbounded_array_v<T(&&)[3]>));
    assert(!(etl::is_unbounded_array_v<T(&&)[]>));

    using etl::is_same_v;
    using etl::remove_volatile_t;

    assert((is_same_v<remove_volatile_t<TC>, TC>));
    assert((is_same_v<remove_volatile_t<TV>, T>));
    assert((is_same_v<remove_volatile_t<TCV>, TC>));

    using etl::remove_const_t;

    assert((is_same_v<remove_const_t<TC>, T>));
    assert((is_same_v<remove_const_t<TV>, TV>));
    assert((is_same_v<remove_const_t<TCV>, TV>));
    assert((is_same_v<remove_const_t<T>, T>));
    assert((is_same_v<remove_const_t<TC>, T>));
    assert((is_same_v<remove_const_t<T[42]>, T[42]>));
    assert((is_same_v<remove_const_t<TC[42]>, T[42]>));
    assert((is_same_v<remove_const_t<T[]>, T[]>));
    assert((is_same_v<remove_const_t<TC[]>, T[]>));
    assert((is_same_v<remove_const_t<T&>, T&>));
    assert((is_same_v<remove_const_t<TC&>, TC&>));
    assert((is_same_v<remove_const_t<T&&>, T&&>));
    assert((is_same_v<remove_const_t<TC&&>, TC&&>));
    assert((is_same_v<remove_const_t<T(T)>, T(T)>));

    using etl::remove_cv_t;
    assert((is_same_v<remove_cv_t<TC>, T>));
    assert((is_same_v<remove_cv_t<TV>, T>));
    assert((is_same_v<remove_cv_t<TCV>, T>));

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

    // assert(test<float>());
    // assert(test<double>());
    // assert(test<long double>());

    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}