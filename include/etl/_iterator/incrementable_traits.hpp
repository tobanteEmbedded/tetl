// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#ifndef TETL_ITERATOR_INCREMENTABLE_TRAITS_HPP
#define TETL_ITERATOR_INCREMENTABLE_TRAITS_HPP

#include <etl/_concepts/integral.hpp>
#include <etl/_cstddef/ptrdiff_t.hpp>
#include <etl/_type_traits/declval.hpp>
#include <etl/_type_traits/is_object.hpp>
#include <etl/_type_traits/make_signed.hpp>

namespace etl {

namespace detail {
template <typename T>
concept has_difference_type = requires { typename T::difference_type; };
} // namespace detail

template <typename I>
struct incrementable_traits { };

template <typename T>
struct incrementable_traits<T const> : incrementable_traits<T> { };

template <typename T>
    requires etl::is_object_v<T>
struct incrementable_traits<T*> {
    using difference_type = etl::ptrdiff_t;
};

template <typename T>
    requires detail::has_difference_type<T>
struct incrementable_traits<T> {
    using difference_type = typename T::difference_type;
};

// clang-format off
template <typename T>
    requires(not detail::has_difference_type<T>) and requires(T const& a, T const& b) {
        { a - b } -> etl::integral;
    }
struct incrementable_traits<T> {
    using difference_type = etl::make_signed_t<decltype(etl::declval<T>() - etl::declval<T>())>;
};

// clang-format on

} // namespace etl

#endif // TETL_ITERATOR_INCREMENTABLE_TRAITS_HPP
