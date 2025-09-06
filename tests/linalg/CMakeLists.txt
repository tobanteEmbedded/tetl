# SPDX-License-Identifier: BSL-1.0
# SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch
project(linalg)

tetl_add_test(${PROJECT_NAME} blas1_add)
tetl_add_test(${PROJECT_NAME} blas1_copy)
tetl_add_test(${PROJECT_NAME} blas1_matrix_frob_norm)
tetl_add_test(${PROJECT_NAME} blas1_scale)
tetl_add_test(${PROJECT_NAME} blas1_scaled)
tetl_add_test(${PROJECT_NAME} blas1_swap_elements_signed)
tetl_add_test(${PROJECT_NAME} blas1_swap_elements_unsigned)
tetl_add_test(${PROJECT_NAME} blas1_vector_abs_sum)
tetl_add_test(${PROJECT_NAME} blas1_vector_idx_abs_max)
tetl_add_test(${PROJECT_NAME} blas1_vector_two_norm)
tetl_add_test(${PROJECT_NAME} blas2_matrix_vector_product)
tetl_add_test(${PROJECT_NAME} concepts)
tetl_add_test(${PROJECT_NAME} conjugated)
tetl_add_test(${PROJECT_NAME} layout_transpose)
