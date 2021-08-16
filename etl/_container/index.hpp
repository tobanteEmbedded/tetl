// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

#ifndef TETL_CONTAINER_INDEX_HPP
#define TETL_CONTAINER_INDEX_HPP

#include "etl/_assert/macro.hpp"
#include "etl/_concepts/emulation.hpp"
#include "etl/_concepts/requires.hpp"
#include "etl/_cstddef/ptrdiff_t.hpp"
#include "etl/_iterator/begin.hpp"
#include "etl/_iterator/end.hpp"
#include "etl/_utility/forward.hpp"

namespace etl::detail {

/// \brief Index a range doing bound checks in debug builds
template <typename Rng, typename Index, TETL_REQUIRES_(RandomAccessRange<Rng>)>
constexpr auto index(Rng&& rng, Index&& i) noexcept -> decltype(auto)
{
    using ::etl::begin;
    using ::etl::end;
    using ::etl::forward;
    using ::etl::ptrdiff_t;

    TETL_ASSERT(static_cast<ptrdiff_t>(i) < (end(rng) - begin(rng)));
    return begin(forward<Rng>(rng))[forward<Index>(i)];
}
} // namespace etl::detail

#endif // TETL_CONTAINER_INDEX_HPP