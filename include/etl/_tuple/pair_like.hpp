// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TUPLE_PAIR_LIKE_HPP
#define TETL_TUPLE_PAIR_LIKE_HPP

#include <etl/_tuple/tuple_like.hpp>
#include <etl/_tuple/tuple_size.hpp>
#include <etl/_type_traits/remove_cvref.hpp>

namespace etl {

template <typename T>
concept pair_like = etl::tuple_like<T> and etl::tuple_size_v<etl::remove_cvref_t<T>> == 2;

} // namespace etl

#endif // TETL_TUPLE_PAIR_LIKE_HPP
