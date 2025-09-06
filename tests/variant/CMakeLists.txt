# SPDX-License-Identifier: BSL-1.0
# SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch
project(variant)

tetl_add_test(${PROJECT_NAME} bad_variant_access)
tetl_add_test(${PROJECT_NAME} monostate)
tetl_add_test(${PROJECT_NAME} variadic_union)
tetl_add_test(${PROJECT_NAME} variant)
tetl_add_test(${PROJECT_NAME} variant2)
