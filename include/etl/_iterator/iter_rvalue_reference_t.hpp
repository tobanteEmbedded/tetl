// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ITERATOR_ITER_RVALUE_REFERENCE_T_HPP
#define TETL_ITERATOR_ITER_RVALUE_REFERENCE_T_HPP

#include <etl/_iterator/dereferenceable.hpp>
#include <etl/_iterator/ranges_iter_move.hpp>
#include <etl/_type_traits/declval.hpp>

namespace etl {

template <etl::detail::dereferenceable T>
    requires requires { etl::ranges::iter_move(etl::declval<T&>()); }
using iter_rvalue_reference_t = decltype(etl::ranges::iter_move(etl::declval<T&>()));

} // namespace etl

#endif // TETL_ITERATOR_ITER_RVALUE_REFERENCE_T_HPP
