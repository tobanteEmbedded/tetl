// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_INDEX_CONSTANT_HPP
#define TETL_TYPE_TRAITS_INDEX_CONSTANT_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_type_traits/integral_constant.hpp>

namespace etl {

template <etl::size_t I>
using index_constant = etl::integral_constant<etl::size_t, I>;

template <etl::size_t I>
inline constexpr auto index_v = etl::index_constant<I>{};

} // namespace etl

#endif // TETL_TYPE_TRAITS_INDEX_CONSTANT_HPP
