# SPDX-License-Identifier: BSL-1.0
# SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch
project(type_traits)

tetl_add_test(${PROJECT_NAME} common_reference)
tetl_add_test(${PROJECT_NAME} copy_cv)
tetl_add_test(${PROJECT_NAME} type_traits)
tetl_add_test(${PROJECT_NAME} type_traits2)
tetl_add_test(${PROJECT_NAME} type_traits3)
tetl_add_test(${PROJECT_NAME} type_traits4)
tetl_add_test(${PROJECT_NAME} underlying_type)
