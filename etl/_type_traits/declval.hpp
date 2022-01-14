/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_DECLVAL_HPP
#define TETL_TYPE_TRAITS_DECLVAL_HPP

#include "etl/_type_traits/add_rvalue_reference.hpp"

namespace etl {

template <typename T>
auto declval() noexcept -> etl::add_rvalue_reference_t<T>;

} // namespace etl

#endif // TETL_TYPE_TRAITS_DECLVAL_HPP