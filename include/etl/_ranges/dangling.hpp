// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#ifndef TETL_RANGES_DANGLING_HPP
#define TETL_RANGES_DANGLING_HPP

namespace etl::ranges {

/// \ingroup ranges
struct dangling {
    constexpr dangling() noexcept = default;

    template <typename... Args>
    constexpr dangling(Args&&... /*args*/) noexcept
    {
    }
};

} // namespace etl::ranges

#endif // TETL_RANGES_DANGLING_HPP
