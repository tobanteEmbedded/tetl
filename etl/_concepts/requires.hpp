// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

#ifndef TETL_DETAIL_TYPE_TRAITS_REQUIRE_MACRO_HPP
#define TETL_DETAIL_TYPE_TRAITS_REQUIRE_MACRO_HPP

#include "etl/_config/preprocessor.hpp"
#include "etl/_type_traits/enable_if.hpp"

/// \brief Requires-clause emulation with SFINAE (for templates).
/// Copied from https://github.com/gnzlbg/static_vector
#define TETL_REQUIRES_(...)                                                    \
    int TETL_CONCAT(_concept_requires_, __LINE__)                              \
        = 42,                                                                  \
        ::etl::enable_if_t < (TETL_CONCAT(_concept_requires_, __LINE__) == 43) \
            || (__VA_ARGS__),                                                  \
        int > = 0

/// \brief Requires-clause emulation with SFINAE (for "non-templates").
/// Copied from https://github.com/gnzlbg/static_vector
#define TETL_REQUIRES(...)                                                     \
    template <int TETL_CONCAT(_concept_requires_, __LINE__) = 42,              \
        ::etl::enable_if_t<(TETL_CONCAT(_concept_requires_, __LINE__) == 43)   \
                               || (__VA_ARGS__),                               \
            int>                                            = 0>

#endif // TETL_DETAIL_TYPE_TRAITS_REQUIRE_MACRO_HPP