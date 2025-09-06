// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_ALGORITHM_FIND_HPP
#define TETL_ALGORITHM_FIND_HPP

namespace etl {

/// Searches for an element equal to value.
///
/// \param first The range of elements to examine.
/// \param last The range of elements to examine.
/// \param value Value to compare the elements to.
///
/// https://en.cppreference.com/w/cpp/algorithm/find
///
/// \ingroup algorithm
template <typename InputIt, typename T>
[[nodiscard]] constexpr auto find(InputIt first, InputIt last, T const& value) noexcept -> InputIt
{
    for (; first != last; ++first) {
        if (*first == value) {
            return first;
        }
    }
    return last;
}

} // namespace etl

#endif // TETL_ALGORITHM_FIND_HPP
