# SPDX-License-Identifier: BSL-1.0
# SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch
project(mutex)

tetl_add_test(${PROJECT_NAME} unique_lock)
tetl_add_test(${PROJECT_NAME} lock_guard)
