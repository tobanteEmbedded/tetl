/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_STACK_HPP
#define TETL_STACK_HPP

#include "etl/_config/all.hpp"

#include "etl/_concepts/requires.hpp"
#include "etl/_iterator/begin.hpp"
#include "etl/_iterator/data.hpp"
#include "etl/_iterator/end.hpp"
#include "etl/_iterator/rbegin.hpp"
#include "etl/_iterator/rend.hpp"
#include "etl/_iterator/size.hpp"
#include "etl/_type_traits/declval.hpp"
#include "etl/_type_traits/is_nothrow_swappable.hpp"
#include "etl/_type_traits/is_swappable.hpp"
#include "etl/_utility/forward.hpp"
#include "etl/_utility/move.hpp"

namespace etl {
/// \brief The stack class is a container adapter that gives the programmer
/// the functionality of a stack - specifically, a LIFO (last-in, first-out)
/// data structure.
///
/// \details The class template acts as a wrapper to the underlying container -
/// only a specific set of functions is provided. The stack pushes and pops the
/// element from the back of the underlying container, known as the top of the
/// stack.
/// \module Containers
template <typename T, typename Container>
struct stack {
    using value_type      = typename Container::value_type;
    using reference       = typename Container::reference;
    using const_reference = typename Container::const_reference;
    using size_type       = typename Container::size_type;
    using container_type  = Container;

    /// \brief Default constructor. Value-initializes the container.
    constexpr stack() : stack { Container {} } { }

    /// \brief Copy-constructs the underlying container c with the contents of
    /// cont.
    constexpr explicit stack(Container const& cont) : c { cont } { }

    /// \brief Move-constructs the underlying container c with cont .
    constexpr explicit stack(Container&& cont) : c { move(cont) } { }

    /// \brief Copy constructor.
    constexpr stack(stack const& other) = default;

    /// \brief Move constructor.
    constexpr stack(stack&& other) noexcept = default;

    /// \brief Checks if the underlying container has no elements.
    [[nodiscard]] constexpr auto empty() const
        noexcept(noexcept(declval<Container>().empty())) -> bool
    {
        return c.empty();
    }

    /// \brief Returns the number of elements in the underlying container.
    [[nodiscard]] constexpr auto size() const
        noexcept(noexcept(declval<Container>().size())) -> size_type
    {
        return c.size();
    }

    /// \brief Returns reference to the top element in the stack. This is the
    /// most recently pushed element. This element will be removed on a call to
    /// pop().
    [[nodiscard]] constexpr auto top() noexcept(
        noexcept(declval<Container>().back())) -> reference
    {
        return c.back();
    }

    /// \brief Returns reference to the top element in the stack. This is the
    /// most recently pushed element. This element will be removed on a call to
    /// pop().
    [[nodiscard]] constexpr auto top() const
        noexcept(noexcept(declval<Container>().back())) -> const_reference
    {
        return c.back();
    }

    /// \brief Pushes the given element value to the top of the stack.
    constexpr auto push(value_type const& x) noexcept(
        noexcept(declval<Container>().push_back(x))) -> void
    {
        c.push_back(x);
    }

    /// \brief Pushes the given element value to the top of the stack.
    constexpr auto push(value_type&& x) noexcept(
        noexcept(declval<Container>().push_back(move(x)))) -> void
    {
        c.push_back(move(x));
    }

    /// \brief Pushes a new element on top of the stack. The element is
    /// constructed in-place, i.e. no copy or move operations are performed. The
    /// constructor of the element is called with exactly the same arguments as
    /// supplied to the function.
    template <typename... Args>
    constexpr auto emplace(Args&&... args) noexcept(
        noexcept(declval<Container>().emplace_back(forward<Args>(args)...)))
        -> decltype(auto)
    {
        return c.emplace_back(forward<Args>(args)...);
    }

    /// \brief Removes the top element from the stack.
    /// \complexity Equal to the complexity of Container::pop_back.
    constexpr auto pop() noexcept(noexcept(declval<Container>().pop_back()))
        -> void
    {
        c.pop_back();
    }

    /// \brief Exchanges the contents of the container adaptor with those of
    /// other.
    constexpr auto swap(stack& s) noexcept(is_nothrow_swappable_v<Container>)
        -> void
    {
        using etl::swap;
        swap(c, s.c);
    }

    /// \brief Compares the contents of the underlying containers of two
    /// container adaptors. The comparison is done by applying the corresponding
    /// operator to the underlying containers.
    [[nodiscard]] friend constexpr auto operator==(stack const& lhs,
        stack const& rhs) noexcept(noexcept(lhs.c == rhs.c)) -> bool
    {
        return lhs.c == rhs.c;
    }

    /// \brief Compares the contents of the underlying containers of two
    /// container adaptors. The comparison is done by applying the corresponding
    /// operator to the underlying containers.
    [[nodiscard]] friend constexpr auto operator!=(stack const& lhs,
        stack const& rhs) noexcept(noexcept(lhs.c != rhs.c)) -> bool
    {
        return lhs.c != rhs.c;
    }

    /// \brief Compares the contents of the underlying containers of two
    /// container adaptors. The comparison is done by applying the corresponding
    /// operator to the underlying containers.
    [[nodiscard]] friend constexpr auto operator<(stack const& lhs,
        stack const& rhs) noexcept(noexcept(lhs.c < rhs.c)) -> bool
    {
        return lhs.c < rhs.c;
    }

    /// \brief Compares the contents of the underlying containers of two
    /// container adaptors. The comparison is done by applying the corresponding
    /// operator to the underlying containers.
    [[nodiscard]] friend constexpr auto operator<=(stack const& lhs,
        stack const& rhs) noexcept(noexcept(lhs.c <= rhs.c)) -> bool
    {
        return lhs.c <= rhs.c;
    }

    /// \brief Compares the contents of the underlying containers of two
    /// container adaptors. The comparison is done by applying the corresponding
    /// operator to the underlying containers.
    [[nodiscard]] friend constexpr auto operator>(stack const& lhs,
        stack const& rhs) noexcept(noexcept(lhs.c > rhs.c)) -> bool
    {
        return lhs.c > rhs.c;
    }

    /// \brief Compares the contents of the underlying containers of two
    /// container adaptors. The comparison is done by applying the corresponding
    /// operator to the underlying containers.
    [[nodiscard]] friend constexpr auto operator>=(stack const& lhs,
        stack const& rhs) noexcept(noexcept(lhs.c >= rhs.c)) -> bool
    {
        return lhs.c >= rhs.c;
    }

protected:
    Container c;
};

// These deduction guides are provided for stack to allow deduction from
// underlying container type.
template <typename Container>
stack(Container) -> stack<typename Container::value_type, Container>;

/// \brief Specializes the swap algorithm for stack. Swaps the contents of lhs
/// and rhs. This overload only participates in overload resolution if
/// is_swappable<C>::value is true.
template <typename T, typename C>
constexpr auto swap(stack<T, C>& lhs, stack<T, C>& rhs) noexcept(
    noexcept(lhs.swap(rhs))) -> enable_if_t<is_swappable_v<C>, void>
{
    lhs.swap(rhs);
}

} // namespace etl

#endif // TETL_STACK_HPP