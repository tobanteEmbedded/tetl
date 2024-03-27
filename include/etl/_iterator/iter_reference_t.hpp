// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ITERATOR_ITER_REFERENCE_T_HPP
#define TETL_ITERATOR_ITER_REFERENCE_T_HPP

#include <etl/_iterator/dereferenceable.hpp>
#include <etl/_type_traits/declval.hpp>

namespace etl {

template <etl::detail::dereferenceable T>
using iter_reference_t = decltype(*etl::declval<T&>());

} // namespace etl

#endif // TETL_ITERATOR_ITER_REFERENCE_T_HPP
