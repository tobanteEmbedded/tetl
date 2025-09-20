// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

#ifndef TETL_TYPE_TRAITS_COPY_CV_HPP
#define TETL_TYPE_TRAITS_COPY_CV_HPP

#include <etl/_type_traits/add_const.hpp>
#include <etl/_type_traits/add_cv.hpp>
#include <etl/_type_traits/add_volatile.hpp>

namespace etl {

/// \ingroup type_traits
template <typename From, typename T0>
struct copy_cv {
    using type = T0;
};

template <typename From, typename T0>
struct copy_cv<From const, T0> {
    using type = add_const_t<T0>;
};

template <typename From, typename T0>
struct copy_cv<From volatile, T0> {
    using type = add_volatile_t<T0>;
};

template <typename From, typename T0>
struct copy_cv<From const volatile, T0> {
    using type = add_cv_t<T0>;
};

/// \ingroup type_traits
/// \relates copy_cv
template <typename From, typename To>
using copy_cv_t = typename copy_cv<From, To>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_COPY_CV_HPP
