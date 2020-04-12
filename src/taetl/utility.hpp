#ifndef TOBANTEAUDIOEMBEDDEDTEMPLATELIBRARY_UTILITY_HPP
#define TOBANTEAUDIOEMBEDDEDTEMPLATELIBRARY_UTILITY_HPP

#include "taetl/type_traits.hpp"

namespace taetl
{
template <class T>
constexpr auto forward(taetl::remove_reference_t<T>& param) noexcept -> T&&
{
    return static_cast<T&&>(param);
}

template <class T>
constexpr auto forward(taetl::remove_reference_t<T>&& param) noexcept -> T&&
{
    return static_cast<T&&>(param);
}
}  // namespace taetl

#endif  // TOBANTEAUDIOEMBEDDEDTEMPLATELIBRARY_UTILITY_HPP
