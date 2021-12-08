/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_RANGES_DECAY_COPY_HPP
#define TETL_RANGES_DECAY_COPY_HPP

#include "etl/_type_traits/decay.hpp"
#include "etl/_type_traits/is_nothrow_convertible.hpp"
#include "etl/_utility/forward.hpp"

#if defined(__cpp_concepts)

namespace etl {

/// \todo Add noexcept
template <typename T>
constexpr auto decay_copy(T&& t) noexcept(
    is_nothrow_convertible_v<T, decay_t<T>>) -> decay_t<T>
{
    return forward<T>(t);
}

} // namespace etl

#endif

#endif // TETL_RANGES_DECAY_COPY_HPP