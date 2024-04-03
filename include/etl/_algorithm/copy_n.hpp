// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ALGORITHM_COPY_N_HPP
#define TETL_ALGORITHM_COPY_N_HPP

namespace etl {

/// Copies exactly count values from the range beginning at first to the
/// range beginning at result. Formally, for each integer `0 <= i < count`,
/// performs `*(result + i) = *(first + i)`. Overlap of ranges is formally
/// permitted, but leads to unpredictable ordering of the results.
///
/// \returns Iterator in the destination range, pointing past the last element
/// copied if count>0 or result otherwise.
/// \ingroup algorithm
template <typename InputIt, typename Size, typename OutputIt>
constexpr auto copy_n(InputIt first, Size count, OutputIt result) -> OutputIt
{
    if (count > 0) {
        *result = *first;
        for (Size i = 1; i < count; ++i) {
            *(++result) = *(++first);
        }
    }
    return result;
}

} // namespace etl

#endif // TETL_ALGORITHM_COPY_N_HPP
