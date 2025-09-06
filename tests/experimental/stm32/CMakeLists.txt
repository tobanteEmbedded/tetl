# SPDX-License-Identifier: BSL-1.0
# SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch
project(experimental_stm32)

tetl_add_test(${PROJECT_NAME} gpio)
tetl_add_test(${PROJECT_NAME} interrupt)
