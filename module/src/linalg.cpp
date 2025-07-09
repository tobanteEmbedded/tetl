module;

#include <etl/linalg.hpp>

export module etl.linalg;

export namespace etl {

namespace linalg {
using etl::linalg::accessor_conjugate;
using etl::linalg::accessor_scaled;
using etl::linalg::add;
using etl::linalg::column_major;
using etl::linalg::column_major_t;
using etl::linalg::conjugated;
using etl::linalg::copy;
using etl::linalg::explicit_diagonal;
using etl::linalg::explicit_diagonal_t;
using etl::linalg::idx_abs_max;
using etl::linalg::implicit_unit_diagonal;
using etl::linalg::implicit_unit_diagonal_t;
using etl::linalg::layout_transpose;
using etl::linalg::lower_triangle;
using etl::linalg::lower_triangle_t;
using etl::linalg::matrix_frob_norm;
using etl::linalg::matrix_vector_product;
using etl::linalg::row_major;
using etl::linalg::row_major_t;
using etl::linalg::scale;
using etl::linalg::scaled;
using etl::linalg::swap_elements;
using etl::linalg::upper_triangle;
using etl::linalg::upper_triangle_t;
using etl::linalg::vector_abs_sum;
using etl::linalg::vector_two_norm;

namespace detail {
using etl::linalg::detail::has_adl_abs;
using etl::linalg::detail::has_adl_conj;
using etl::linalg::detail::has_adl_imag;
using etl::linalg::detail::has_adl_real;
using etl::linalg::detail::transpose_extents;
using etl::linalg::detail::transpose_extents_t;
} // namespace detail

} // namespace linalg

} // namespace etl
