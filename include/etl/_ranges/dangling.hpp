// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_RANGES_DANGLING_HPP
#define TETL_RANGES_DANGLING_HPP

namespace etl::ranges {

struct dangling {
    constexpr dangling() noexcept = default;

    template <typename... Args>
    constexpr dangling(Args&&...) noexcept
    {
    }
};

} // namespace etl::ranges

#endif // TETL_RANGES_DANGLING_HPP
