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

template <class T1, class T2>
struct pair
{
    using first_type  = T1;
    using second_type = T2;

    pair() : first {}, second {} { }
    T1 first;
    T2 second;
};
}  // namespace taetl

#endif  // TOBANTEAUDIOEMBEDDEDTEMPLATELIBRARY_UTILITY_HPP
