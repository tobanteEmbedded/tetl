// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_CONCEPTS_COPY_CONSTRUCTIBLE_HPP
#define TETL_CONCEPTS_COPY_CONSTRUCTIBLE_HPP

#include <etl/_concepts/constructible_from.hpp>
#include <etl/_concepts/convertible_to.hpp>
#include <etl/_concepts/move_constructible.hpp>

namespace etl {

/// \brief The concept copy_constructible is satisfied if T is an lvalue
/// reference type, or if it is a move_constructible object type where an object
/// of that type can constructed from a (possibly const) lvalue or const rvalue
/// of that type in both direct- and copy-initialization contexts with the usual
/// semantics (a copy is constructed with the source unchanged).
/// \ingroup concepts
template <typename T>
concept copy_constructible = move_constructible<T>
                         and constructible_from<T, T&>
                         and convertible_to<T&, T>
                         and constructible_from<T, T const&>
                         and convertible_to<T const&, T>
                         and constructible_from<T, T const>
                         and convertible_to<T const, T>;

} // namespace etl

#endif // TETL_CONCEPTS_COPY_CONSTRUCTIBLE_HPP
