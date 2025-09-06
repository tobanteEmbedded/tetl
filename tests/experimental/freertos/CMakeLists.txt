# SPDX-License-Identifier: BSL-1.0
# SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch
project(experimental_freertos)

tetl_add_test(${PROJECT_NAME} queue)
tetl_add_test(${PROJECT_NAME} stream_buffer)
tetl_add_test(${PROJECT_NAME} task)
