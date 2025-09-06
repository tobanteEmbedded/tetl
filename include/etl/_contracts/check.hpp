// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#ifndef TETL_CONTRACTS_CHECK_HPP
#define TETL_CONTRACTS_CHECK_HPP

#include <etl/_cassert/assert.hpp>
#include <etl/_type_traits/is_constant_evaluated.hpp>

#if defined(TETL_ENABLE_CONTRACT_CHECKS_SAFE)
    #define TETL_PRECONDITION_SAFE(...) TETL_ASSERT_IMPL(__VA_ARGS__)
    #define TETL_PRECONDITION(...)      TETL_ASSERT_IMPL(__VA_ARGS__)
#elif defined(TETL_ENABLE_CONTRACT_CHECKS)
    #define TETL_PRECONDITION(...) TETL_ASSERT_IMPL(__VA_ARGS__)
    #define TETL_PRECONDITION_SAFE(...)
#else
    #define TETL_PRECONDITION(...)
    #define TETL_PRECONDITION_SAFE(...)
#endif

#endif // TETL_CONTRACTS_CHECK_HPP
