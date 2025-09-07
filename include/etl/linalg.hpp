// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#ifndef TETL_LINALG_HPP
#define TETL_LINALG_HPP

/// \defgroup linalg linalg
/// Basic linear algebra algorithms
/// \ingroup numerics-library
/// \code{.cpp}
/// #include <etl/linalg.hpp>
/// \endcode

#include <etl/_config/all.hpp>

#include <etl/_linalg/accessor_conjugate.hpp>
#include <etl/_linalg/accessor_scaled.hpp>
#include <etl/_linalg/blas1_add.hpp>
#include <etl/_linalg/blas1_copy.hpp>
#include <etl/_linalg/blas1_matrix_frob_norm.hpp>
#include <etl/_linalg/blas1_scale.hpp>
#include <etl/_linalg/blas1_scaled.hpp>
#include <etl/_linalg/blas1_swap_elements.hpp>
#include <etl/_linalg/blas1_vector_abs_sum.hpp>
#include <etl/_linalg/blas1_vector_idx_abs_max.hpp>
#include <etl/_linalg/blas1_vector_two_norm.hpp>
#include <etl/_linalg/blas2_matrix_vector_product.hpp>
#include <etl/_linalg/blas3_matrix_product.hpp>
#include <etl/_linalg/conjugated.hpp>
#include <etl/_linalg/layout_transpose.hpp>
#include <etl/_linalg/tags.hpp>

#endif // TETL_LINALG_HPP
