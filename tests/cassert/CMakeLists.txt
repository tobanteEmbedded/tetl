# SPDX-License-Identifier: BSL-1.0
# SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch
project(cassert)

tetl_add_test(${PROJECT_NAME} assert WILL_FAIL TRUE)

# Test default assert_handler. Don't use `tetl_add_test`
add_executable(test_cassert_assert_handler "assert_handler.t.cpp")
target_compile_definitions(test_cassert_assert_handler PRIVATE TETL_ENABLE_ASSERTIONS=1)
target_link_libraries(test_cassert_assert_handler PRIVATE tetl::etl tetl::compiler_warnings)
add_test(NAME "cassert.hpp: assert_handler" COMMAND test_cassert_assert_handler)
set_tests_properties("cassert.hpp: assert_handler" PROPERTIES WILL_FAIL TRUE)
