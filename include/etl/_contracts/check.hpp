// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CONTRACTS_CHECK_HPP
#define TETL_CONTRACTS_CHECK_HPP

#include <etl/_cassert/assert.hpp>

#if defined(TETL_ENABLE_CONTRACT_CHECKS)
    #define TETL_PRECONDITION(...) TETL_ASSERT_IMPL(__VA_ARGS__)
#else
    #define TETL_PRECONDITION(...)
#endif

#endif // TETL_CONTRACTS_CHECK_HPP
