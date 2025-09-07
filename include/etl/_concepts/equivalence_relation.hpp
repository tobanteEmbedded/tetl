// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#ifndef TETL_CONCEPTS_EQUIVALENCE_RELATION_HPP
#define TETL_CONCEPTS_EQUIVALENCE_RELATION_HPP

#include <etl/_concepts/relation.hpp>

namespace etl {

/// \ingroup concepts
template <typename R, typename T, typename U>
concept equivalence_relation = relation<R, T, U>;

} // namespace etl

#endif // TETL_CONCEPTS_EQUIVALENCE_RELATION_HPP
