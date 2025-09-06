# SPDX-License-Identifier: BSL-1.0
# SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch
project(functional)

tetl_add_test(${PROJECT_NAME} function_ref)
tetl_add_test(${PROJECT_NAME} hash)
tetl_add_test(${PROJECT_NAME} inplace_function)
tetl_add_test(${PROJECT_NAME} invoke)
tetl_add_test(${PROJECT_NAME} operations)
tetl_add_test(${PROJECT_NAME} reference_wrapper)
