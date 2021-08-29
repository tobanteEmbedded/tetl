/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CONTAINER_INDEX_HPP
#define TETL_CONTAINER_INDEX_HPP

#include "etl/_cassert/macro.hpp"
#include "etl/_concepts/emulation.hpp"
#include "etl/_concepts/requires.hpp"
#include "etl/_cstddef/ptrdiff_t.hpp"
#include "etl/_iterator/begin.hpp"
#include "etl/_iterator/end.hpp"
#include "etl/_utility/forward.hpp"

namespace etl::detail {

/// \brief Index a range doing bound checks in debug builds
/// Copied from https://github.com/gnzlbg/static_vector
template <typename Rng, typename Index, TETL_REQUIRES_(RandomAccessRange<Rng>)>
constexpr auto index(Rng&& rng, Index&& i) noexcept -> decltype(auto)
{
    using etl::begin;
    using etl::end;
    using etl::forward;
    using etl::ptrdiff_t;

    TETL_ASSERT(static_cast<ptrdiff_t>(i) < (end(rng) - begin(rng)));
    return begin(forward<Rng>(rng))[forward<Index>(i)];
}
} // namespace etl::detail

#endif // TETL_CONTAINER_INDEX_HPP