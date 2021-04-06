#ifndef TAETL_EXPECTED_HPP
#define TAETL_EXPECTED_HPP

#include "etl/type_traits.hpp"

namespace etl
{
struct unexpect_t
{
  unexpect_t() = default;
};

inline constexpr unexpect_t unexpect {};

}  // namespace etl
#endif  // TAETL_EXPECTED_HPP
