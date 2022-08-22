/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CONCEPTS_REQUIRES_HPP
#define TETL_CONCEPTS_REQUIRES_HPP

#include "etl/_config/all.hpp"
#include "etl/_type_traits/enable_if.hpp"

/// \brief Requires-clause emulation with SFINAE (for templates).
/// Copied from https://github.com/gnzlbg/static_vector
#define TETL_REQUIRES_(...)                                                                                            \
    int TETL_PP_CONCAT(_concept_requires_, __LINE__)                                                                   \
        = 42,                                                                                                          \
        etl::enable_if_t < (TETL_PP_CONCAT(_concept_requires_, __LINE__) == 43) || (__VA_ARGS__), int > = 0

/// \brief Requires-clause emulation with SFINAE (for "non-templates").
/// Copied from https://github.com/gnzlbg/static_vector
#define TETL_REQUIRES(...)                                                                                             \
    template <int TETL_PP_CONCAT(_concept_requires_, __LINE__)                                       = 42,             \
        etl::enable_if_t<(TETL_PP_CONCAT(_concept_requires_, __LINE__) == 43) || (__VA_ARGS__), int> = 0>

#endif // TETL_CONCEPTS_REQUIRES_HPP
