# SPDX-License-Identifier: BSL-1.0
# SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch
project("string")

tetl_add_test(${PROJECT_NAME} basic_inplace_string)
tetl_add_test(${PROJECT_NAME} char_traits)
tetl_add_test(${PROJECT_NAME} inplace_string.access)
tetl_add_test(${PROJECT_NAME} inplace_string.algorithm)
tetl_add_test(${PROJECT_NAME} inplace_string.compare)
tetl_add_test(${PROJECT_NAME} inplace_string.construct)
tetl_add_test(${PROJECT_NAME} inplace_string.modify)
tetl_add_test(${PROJECT_NAME} inplace_u8string)
tetl_add_test(${PROJECT_NAME} inplace_u16string)
tetl_add_test(${PROJECT_NAME} inplace_u32string)
tetl_add_test(${PROJECT_NAME} inplace_wstring)
tetl_add_test(${PROJECT_NAME} stod)
tetl_add_test(${PROJECT_NAME} stoi)
tetl_add_test(${PROJECT_NAME} string_constant)
tetl_add_test(${PROJECT_NAME} to_string)
