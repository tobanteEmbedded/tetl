// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#ifndef TETL_MDSPAN_SUBMDSPAN_HPP
#define TETL_MDSPAN_SUBMDSPAN_HPP

#include <etl/_mdspan/mdspan.hpp>

namespace etl {

// template <typename T, typename Ext, typename Layout, typename Accessor, typename...
// SliceSpecifiers>
// [[nodiscard]] constexpr auto submdspan(mdspan<T, Ext, Layout, Accessor> const& src,
// SliceSpecifiers... slices)
// {
//     auto sub_mapping  = submdspan_mapping(src.mapping(), slices...);
//     auto sub_accessor = typename Accessor::offset_policy(src.accessor());
//     auto sub_data     = src.accessor().offset(src.data_handle(), sub_mapping.offset);
//     return etl::mdspan(sub_data, sub_mapping.mapping, sub_accessor);
// }

} // namespace etl

#endif // TETL_MDSPAN_SUBMDSPAN_HPP
