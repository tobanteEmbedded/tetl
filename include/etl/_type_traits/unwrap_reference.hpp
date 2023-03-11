/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_UNWRAP_REFERENCE_HPP
#define TETL_TYPE_TRAITS_UNWRAP_REFERENCE_HPP

#include "etl/_type_traits/conditional.hpp"
#include "etl/_type_traits/decay.hpp"
#include "etl/_type_traits/is_same.hpp"

namespace etl {

template <typename T>
struct reference_wrapper;

template <typename T>
struct unwrap_reference;

template <typename T>
struct unwrap_reference<etl::reference_wrapper<T>> {
    using type = T&;
};

template <typename T>
struct unwrap_ref_decay
    : etl::conditional_t<!etl::is_same_v<etl::decay_t<T>, T>, unwrap_reference<etl::decay_t<T>>, etl::decay<T>> { };

template <typename T>
using unwrap_ref_decay_t = typename etl::unwrap_ref_decay<T>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_UNWRAP_REFERENCE_HPP
