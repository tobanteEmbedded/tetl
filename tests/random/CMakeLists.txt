# SPDX-License-Identifier: BSL-1.0
# SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch
project(random)

tetl_add_test(${PROJECT_NAME} uniform_int_distribution)
tetl_add_test(${PROJECT_NAME} uniform_real_distribution)
tetl_add_test(${PROJECT_NAME} xorshift)
