// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_UNWRAP_REFERENCE_HPP
#define TETL_TYPE_TRAITS_UNWRAP_REFERENCE_HPP

#include <etl/_type_traits/conditional.hpp>
#include <etl/_type_traits/decay.hpp>
#include <etl/_type_traits/is_same.hpp>

namespace etl {

template <typename T>
struct reference_wrapper;

template <typename T>
struct unwrap_reference;

template <typename T>
struct unwrap_reference<reference_wrapper<T>> {
    using type = T&;
};

template <typename T>
struct unwrap_ref_decay : conditional_t<not is_same_v<decay_t<T>, T>, unwrap_reference<decay_t<T>>, decay<T>> { };

template <typename T>
using unwrap_ref_decay_t = typename unwrap_ref_decay<T>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_UNWRAP_REFERENCE_HPP
