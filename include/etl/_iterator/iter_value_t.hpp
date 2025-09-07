// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#ifndef TETL_ITERATOR_ITER_VALUE_T_HPP
#define TETL_ITERATOR_ITER_VALUE_T_HPP

#include <etl/_iterator/indirectly_readable_traits.hpp>
#include <etl/_iterator/iterator_traits.hpp>
#include <etl/_type_traits/is_specialized.hpp>
#include <etl/_type_traits/remove_cvref.hpp>

namespace etl {

namespace detail {

template <typename T>
struct iter_value {
    using type = typename etl::indirectly_readable_traits<etl::remove_cvref_t<T>>::value_type;
};

template <typename T>
    requires(is_specialized_v<etl::iterator_traits, etl::remove_cvref_t<T>>)
struct iter_value<T> {
    using type = typename etl::iterator_traits<etl::remove_cvref_t<T>>::value_type;
};

} // namespace detail

template <typename T>
using iter_value_t = typename detail::iter_value<T>::type;

} // namespace etl

#endif // TETL_ITERATOR_ITER_VALUE_T_HPP
