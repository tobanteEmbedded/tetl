# SPDX-License-Identifier: BSL-1.0
# SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch
project("strings")

tetl_add_test(${PROJECT_NAME} from_floating_point)
tetl_add_test(${PROJECT_NAME} from_integer)
tetl_add_test(${PROJECT_NAME} to_floating_point)
tetl_add_test(${PROJECT_NAME} to_integer)
