# SPDX-License-Identifier: BSL-1.0
# SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch
project(memory)

tetl_add_test(${PROJECT_NAME} align)
tetl_add_test(${PROJECT_NAME} allocator_traits)
tetl_add_test(${PROJECT_NAME} memory)
tetl_add_test(${PROJECT_NAME} pointer_int_pair)
tetl_add_test(${PROJECT_NAME} small_ptr)
tetl_add_test(${PROJECT_NAME} uninitialized_move)
