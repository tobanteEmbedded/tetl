// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_DECLVAL_HPP
#define TETL_TYPE_TRAITS_DECLVAL_HPP

#include <etl/_type_traits/add_rvalue_reference.hpp>

namespace etl {

template <typename T>
auto declval() noexcept -> add_rvalue_reference_t<T>;

} // namespace etl

#endif // TETL_TYPE_TRAITS_DECLVAL_HPP
