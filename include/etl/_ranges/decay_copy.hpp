// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_RANGES_DECAY_COPY_HPP
#define TETL_RANGES_DECAY_COPY_HPP

#include "etl/_type_traits/decay.hpp"
#include "etl/_type_traits/is_nothrow_convertible.hpp"
#include "etl/_utility/forward.hpp"

namespace etl {

template <typename T>
constexpr auto decay_copy(T&& t) noexcept(is_nothrow_convertible_v<T, decay_t<T>>) -> decay_t<T>
{
    return forward<T>(t);
}

} // namespace etl

#endif // TETL_RANGES_DECAY_COPY_HPP
