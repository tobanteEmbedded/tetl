/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_IS_TRIVIALLY_COPYABLE_HPP
#define TETL_TYPE_TRAITS_IS_TRIVIALLY_COPYABLE_HPP

#include "etl/_type_traits/is_copy_assignable.hpp"
#include "etl/_type_traits/is_copy_constructible.hpp"
#include "etl/_type_traits/is_destructible.hpp"
#include "etl/_type_traits/is_move_assignable.hpp"
#include "etl/_type_traits/is_move_constructible.hpp"

namespace etl {

/// \brief If T is a TriviallyCopyable type, provides the member constant value
/// equal to true. For any other type, value is false. The only trivially
/// copyable types are scalar types, trivially copyable classes, and arrays of
/// such types/classes (possibly cv-qualified).
/// group is_trivial_copyable
template <typename T>
struct is_trivially_copyable {
private:
    // copy constructors
    static constexpr bool has_trivial_copy_ctor = is_copy_constructible_v<T>;
    static constexpr bool has_deleted_copy_ctor = !is_copy_constructible_v<T>;

    // move constructors
    static constexpr bool has_trivial_move_ctor = is_move_constructible_v<T>;
    static constexpr bool has_deleted_move_ctor = !is_move_constructible_v<T>;

    // copy assign
    static constexpr bool has_trivial_copy_assign = is_copy_assignable_v<T>;
    static constexpr bool has_deleted_copy_assign = !is_copy_assignable_v<T>;

    // move assign
    static constexpr bool has_trivial_move_assign = is_move_assignable_v<T>;
    static constexpr bool has_deleted_move_assign = !is_move_assignable_v<T>;

    // destructor
    static constexpr bool has_trivial_dtor = is_destructible_v<T>;

public:
    static constexpr bool value
        = has_trivial_dtor
          && (has_deleted_move_assign || has_trivial_move_assign)
          && (has_deleted_move_ctor || has_trivial_move_ctor)
          && (has_deleted_copy_assign || has_trivial_copy_assign)
          && (has_deleted_copy_ctor || has_trivial_copy_ctor);
};

/// group is_trivial_copyable
template <typename T>
struct is_trivially_copyable<T*> : true_type {
};

template <typename T>
inline constexpr bool is_trivially_copyable_v = is_trivially_copyable<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_TRIVIALLY_COPYABLE_HPP