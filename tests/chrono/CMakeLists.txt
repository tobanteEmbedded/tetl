# SPDX-License-Identifier: BSL-1.0
# SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch
project(chrono)

tetl_add_test(${PROJECT_NAME} calender.day)
tetl_add_test(${PROJECT_NAME} calender.month)
tetl_add_test(${PROJECT_NAME} calender.year)
tetl_add_test(${PROJECT_NAME} duration)
tetl_add_test(${PROJECT_NAME} time_point)
