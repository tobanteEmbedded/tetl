// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CHRONO_DURATION_VALUES_HPP
#define TETL_CHRONO_DURATION_VALUES_HPP

#include "etl/_limits/numeric_limits.hpp"

namespace etl::chrono {
/// \brief The etl::chrono::duration_values type defines three common durations.
/// \details The zero, min, and max methods in etl::chrono::duration forward
/// their work to these methods. This type can be specialized if the
/// representation Rep requires a specific implementation to return these
/// duration objects.
template <typename Rep>
struct duration_values {
public:
    /// \brief Returns a zero-length representation.
    [[nodiscard]] static constexpr auto zero() -> Rep { return Rep{}; }

    /// \brief Returns the smallest possible representation.
    [[nodiscard]] static constexpr auto min() -> Rep { return etl::numeric_limits<Rep>::lowest(); }

    /// \brief Returns the special duration value max.
    [[nodiscard]] static constexpr auto max() -> Rep { return etl::numeric_limits<Rep>::max(); }
};

} // namespace etl::chrono

#endif // TETL_CHRONO_DURATION_VALUES_HPP
