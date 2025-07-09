module;

#include <etl/mdspan.hpp>

export module etl.mdspan;

export namespace etl {

using etl::default_accessor;
using etl::dextents;
using etl::dynamic_extent;
using etl::extents;
using etl::full_extent;
using etl::full_extent_t;
using etl::layout_left;
using etl::layout_right;
using etl::layout_stride;
using etl::mdspan;
using etl::strided_slice;
using etl::submdspan_extents;

} // namespace etl
