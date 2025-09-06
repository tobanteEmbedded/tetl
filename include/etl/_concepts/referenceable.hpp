// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#ifndef TETL_CONCEPTS_REFERENCEABLE_HPP
#define TETL_CONCEPTS_REFERENCEABLE_HPP

#include <etl/_type_traits/is_void.hpp>

namespace etl {

/// \note Non-standard extension
/// \headerfile etl/concepts.hpp
/// \ingroup concepts
template <typename T>
concept referenceable = not etl::is_void_v<T>;

} // namespace etl

#endif // TETL_CONCEPTS_REFERENCEABLE_HPP
