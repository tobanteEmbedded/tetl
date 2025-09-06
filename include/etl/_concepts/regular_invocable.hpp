// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#ifndef TETL_CONCEPTS_REGULAR_INVOCABLE_HPP
#define TETL_CONCEPTS_REGULAR_INVOCABLE_HPP

#include <etl/_concepts/invocable.hpp>

namespace etl {

/// \ingroup concepts
template <typename F, typename... Args>
concept regular_invocable = etl::invocable<F, Args...>;

} // namespace etl

#endif // TETL_CONCEPTS_REGULAR_INVOCABLE_HPP
