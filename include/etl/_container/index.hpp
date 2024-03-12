// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CONTAINER_INDEX_HPP
#define TETL_CONTAINER_INDEX_HPP

#include <etl/_cassert/macro.hpp>
#include <etl/_concepts/emulation.hpp>
#include <etl/_cstddef/ptrdiff_t.hpp>
#include <etl/_iterator/begin.hpp>
#include <etl/_iterator/end.hpp>
#include <etl/_utility/forward.hpp>

namespace etl::detail {

/// \brief Index a range doing bound checks in debug builds
/// Copied from https://github.com/gnzlbg/static_vector
template <typename Rng, typename Index>
    requires(RandomAccessRange<Rng>)
constexpr auto index(Rng&& rng, Index&& i) noexcept -> decltype(auto)
{
    using etl::begin;
    using etl::end;
    using etl::ptrdiff_t;

    TETL_ASSERT(static_cast<ptrdiff_t>(i) < (end(rng) - begin(rng)));
    return begin(TETL_FORWARD(rng))[TETL_FORWARD(i)];
}
} // namespace etl::detail

#endif // TETL_CONTAINER_INDEX_HPP
