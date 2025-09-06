// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#ifndef TETL_TUPLE_TUPLE_LIKE_HPP
#define TETL_TUPLE_TUPLE_LIKE_HPP

#include <etl/_tuple/is_tuple_like.hpp>
#include <etl/_type_traits/remove_cvref.hpp>

namespace etl {

template <typename T>
concept tuple_like = etl::is_tuple_like<etl::remove_cvref_t<T>>;

} // namespace etl

#endif // TETL_TUPLE_TUPLE_LIKE_HPP
