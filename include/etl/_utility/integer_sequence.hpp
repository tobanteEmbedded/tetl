// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_UTILITY_INTEGER_SEQUENCE_HPP
#define TETL_UTILITY_INTEGER_SEQUENCE_HPP

#include <etl/_config/all.hpp>

#include <etl/_cstddef/size_t.hpp>
#include <etl/_type_traits/is_integral.hpp>

namespace etl {

namespace detail {
template <size_t...>
struct tuple_indices { };
} // namespace detail

template <typename T, T... Ints>
struct integer_sequence {
    static_assert(is_integral_v<T>, "T must be an integral type.");

    using value_type = T;

    [[nodiscard]] static constexpr auto size() noexcept -> size_t { return sizeof...(Ints); }

    using to_tuple_indices = typename detail::tuple_indices<Ints...>;
};

template <typename T, T Size>
using make_integer_sequence = TETL_BUILTIN_INT_SEQ(T, Size);

} // namespace etl

#endif // TETL_UTILITY_INTEGER_SEQUENCE_HPP
