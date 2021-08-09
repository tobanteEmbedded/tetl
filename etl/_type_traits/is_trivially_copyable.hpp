// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

#ifndef TETL_DETAIL_TYPE_TRAITS_IS_TRIVIALLY_COPYABLE_HPP
#define TETL_DETAIL_TYPE_TRAITS_IS_TRIVIALLY_COPYABLE_HPP

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

#endif // TETL_DETAIL_TYPE_TRAITS_IS_TRIVIALLY_COPYABLE_HPP