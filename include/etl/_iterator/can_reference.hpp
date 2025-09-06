// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#ifndef TETL_ITERATOR_CAN_REFERENCE_HPP
#define TETL_ITERATOR_CAN_REFERENCE_HPP

namespace etl::detail {

template <typename T>
using with_reference = T&;

template <typename T>
concept can_reference = requires { typename with_reference<T>; };

} // namespace etl::detail

#endif // TETL_ITERATOR_CAN_REFERENCE_HPP
