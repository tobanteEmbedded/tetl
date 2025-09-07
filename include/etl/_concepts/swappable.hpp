// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#ifndef TETL_CONCEPTS_SWAPPABLE_HPP
#define TETL_CONCEPTS_SWAPPABLE_HPP

#include <etl/_utility/swap.hpp>

namespace etl {

/// \todo Convert to ranges::swap once available
/// \ingroup concepts
template <typename T>
concept swappable = requires(T& a, T& b) {
    swap(a, b);
    // ranges::swap(a, b);
};

} // namespace etl

#endif // TETL_CONCEPTS_SWAPPABLE_HPP
