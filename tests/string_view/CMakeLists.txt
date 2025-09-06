# SPDX-License-Identifier: BSL-1.0
# SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch
project(string_view)

tetl_add_test(${PROJECT_NAME} string_view.algorithm)
tetl_add_test(${PROJECT_NAME} string_view.compare)
tetl_add_test(${PROJECT_NAME} string_view)
