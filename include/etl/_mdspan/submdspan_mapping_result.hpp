// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_MDSPAN_SUBMDSPAN_MAPPING_RESULT_HPP
#define TETL_MDSPAN_SUBMDSPAN_MAPPING_RESULT_HPP

#include <etl/_config/all.hpp>

#include <etl/_cstddef/size_t.hpp>

namespace etl {

template <typename LayoutMapping>
struct submdspan_mapping_result {
    TETL_NO_UNIQUE_ADDRESS LayoutMapping mapping = LayoutMapping();
    etl::size_t offset {};
};

} // namespace etl

#endif // TETL_MDSPAN_SUBMDSPAN_MAPPING_RESULT_HPP
