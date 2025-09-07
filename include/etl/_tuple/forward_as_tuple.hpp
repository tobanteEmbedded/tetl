// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_TUPLE_FORWARD_AS_TUPLE_HPP
#define TETL_TUPLE_FORWARD_AS_TUPLE_HPP

#include <etl/_tuple/tuple.hpp>
#include <etl/_utility/forward.hpp>

namespace etl {

/// \brief Constructs a tuple of references to the arguments in args suitable
/// for forwarding as an argument to a function. The tuple has rvalue reference
/// data members when rvalues are used as arguments, and otherwise has lvalue
/// reference data members.
template <typename... Args>
[[nodiscard]] constexpr auto forward_as_tuple(Args&&... args) noexcept -> etl::tuple<Args&&...>
{
    return etl::tuple<Args&&...>{etl::forward<Args>(args)...};
}

} // namespace etl

#endif // TETL_TUPLE_FORWARD_AS_TUPLE_HPP
