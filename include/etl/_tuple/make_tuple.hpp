

// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TUPLE_MAKE_TUPLE_HPP
#define TETL_TUPLE_MAKE_TUPLE_HPP

#include <etl/_functional/reference_wrapper.hpp>
#include <etl/_tuple/tuple.hpp>
#include <etl/_type_traits/decay.hpp>
#include <etl/_utility/forward.hpp>

namespace etl {
namespace detail {
template <typename T>
struct unwrap_refwrapper {
    using type = T;
};

template <typename T>
struct unwrap_refwrapper<reference_wrapper<T>> {
    using type = T&;
};

template <typename T>
using unwrap_decay_t = typename unwrap_refwrapper<decay_t<T>>::type;

} // namespace detail

/// \brief Creates a tuple object, deducing the target type from the types of
/// arguments.
template <typename... Types>
[[nodiscard]] constexpr auto make_tuple(Types&&... args)
{
    return tuple<detail::unwrap_decay_t<Types>...>(TETL_FORWARD(args)...);
}
} // namespace etl

#endif // TETL_TUPLE_MAKE_TUPLE_HPP
