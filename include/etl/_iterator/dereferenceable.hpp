// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ITERATOR_DEREFERENCEABLE_HPP
#define TETL_ITERATOR_DEREFERENCEABLE_HPP

#include <etl/_iterator/can_reference.hpp>
#include <etl/_type_traits/declval.hpp>

namespace etl::detail {

template <typename T>
concept dereferenceable = requires(T& t) {
    *etl::declval<T&>();
    { *t } -> can_reference;
};

} // namespace etl::detail

#endif // TETL_ITERATOR_DEREFERENCEABLE_HPP
