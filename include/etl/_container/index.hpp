// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CONTAINER_INDEX_HPP
#define TETL_CONTAINER_INDEX_HPP

#include <etl/_cassert/assert.hpp>
#include <etl/_concepts/emulation.hpp>
#include <etl/_cstddef/ptrdiff_t.hpp>
#include <etl/_iterator/begin.hpp>
#include <etl/_iterator/end.hpp>
#include <etl/_utility/forward.hpp>

namespace etl::detail {

/// \brief Index a range doing bound checks in debug builds
/// Copied from https://github.com/gnzlbg/static_vector
template <typename Range, typename Index>
    requires(RandomAccessRange<Range>)
constexpr auto index(Range&& rng, Index&& i) noexcept -> decltype(auto)
{
    using etl::begin;
    using etl::end;

    TETL_ASSERT(static_cast<etl::ptrdiff_t>(i) < (end(rng) - begin(rng)));
    return begin(etl::forward<Range>(rng))[etl::forward<Index>(i)];
}
} // namespace etl::detail

#endif // TETL_CONTAINER_INDEX_HPP
