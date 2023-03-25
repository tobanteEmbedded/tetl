/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_MDSPAN_LAYOUT_MAPPING_ALIKE_HPP
#define TETL_MDSPAN_LAYOUT_MAPPING_ALIKE_HPP

#include "etl/_concepts/same_as.hpp"
#include "etl/_mdspan/is_extents.hpp"
#include "etl/_type_traits/bool_constant.hpp"

namespace etl::detail {

// clang-format off
template<class M>
concept layout_mapping_alike = requires {                         // exposition only
  requires detail::is_extents<typename M::extents_type>;
  { M::is_always_strided() } -> same_as<bool>;
  { M::is_always_exhaustive() } -> same_as<bool>;
  { M::is_always_unique() } -> same_as<bool>;
  etl::bool_constant<M::is_always_strided()>::value;
  etl::bool_constant<M::is_always_exhaustive()>::value;
  etl::bool_constant<M::is_always_unique()>::value;
};
// clang-format on

} // namespace etl::detail

#endif // TETL_MDSPAN_LAYOUT_MAPPING_ALIKE_HPP
