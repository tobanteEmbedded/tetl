// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_RANGES_RANGE_HPP
#define TETL_RANGES_RANGE_HPP

#include <etl/_ranges/begin.hpp>
#include <etl/_ranges/end.hpp>

namespace etl::ranges {

template <typename T>
concept range = requires(T& t) {
    etl::ranges::begin(t);
    etl::ranges::end(t);
};

} // namespace etl::ranges

#endif // TETL_RANGES_RANGE_HPP
