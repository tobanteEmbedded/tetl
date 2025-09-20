// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#ifndef TETL_CONCEPTS_COPYABLE_HPP
#define TETL_CONCEPTS_COPYABLE_HPP

#include <etl/_concepts/assignable_from.hpp>
#include <etl/_concepts/copy_constructible.hpp>
#include <etl/_concepts/movable.hpp>

namespace etl {

/// \ingroup concepts
template <typename T>
concept copyable = copy_constructible<T>
               and movable<T>
               and assignable_from<T&, T&>
               and assignable_from<T&, T const&>
               and assignable_from<T&, T const>;

} // namespace etl

#endif // TETL_CONCEPTS_COPYABLE_HPP
