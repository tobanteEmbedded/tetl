// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#ifndef TETL_RANGES_CAN_BORROW_HPP
#define TETL_RANGES_CAN_BORROW_HPP

#include <etl/_ranges/enable_borrowed_range.hpp>
#include <etl/_type_traits/is_lvalue_reference.hpp>
#include <etl/_type_traits/remove_cvref.hpp>

namespace etl::ranges::detail {

/// \ingroup ranges
template <typename T>
concept can_borrow = etl::is_lvalue_reference_v<T> or etl::ranges::enable_borrowed_range<etl::remove_cvref_t<T>>;

} // namespace etl::ranges::detail

#endif // TETL_RANGES_CAN_BORROW_HPP
