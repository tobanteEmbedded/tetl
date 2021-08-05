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

#ifndef TETL_STACK_HPP
#define TETL_STACK_HPP

#include "etl/version.hpp"

#include "etl/iterator.hpp"
#include "etl/type_traits.hpp"

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
class stack {
public:
    using value_type      = typename Container::value_type;
    using reference       = typename Container::reference;
    using const_reference = typename Container::const_reference;
    using size_type       = typename Container::size_type;
    using container_type  = Container;

    /// \brief Default constructor. Value-initializes the container.
    constexpr stack() : stack(Container()) { }

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
        noexcept(noexcept(declval<container_type>().empty())) -> bool
    {
        return c.empty();
    }

    /// \brief Returns the number of elements in the underlying container.
    [[nodiscard]] constexpr auto size() const
        noexcept(noexcept(declval<container_type>().size())) -> size_type
    {
        return c.size();
    }

    /// \brief Returns reference to the top element in the stack. This is the
    /// most recently pushed element. This element will be removed on a call to
    /// pop().
    [[nodiscard]] constexpr auto top() noexcept(
        noexcept(declval<container_type>().back())) -> reference
    {
        return c.back();
    }

    /// \brief Returns reference to the top element in the stack. This is the
    /// most recently pushed element. This element will be removed on a call to
    /// pop().
    [[nodiscard]] constexpr auto top() const
        noexcept(noexcept(declval<container_type>().back())) -> const_reference
    {
        return c.back();
    }

    /// \brief Pushes the given element value to the top of the stack.
    constexpr auto push(value_type const& x) noexcept(
        noexcept(declval<container_type>().push_back(x))) -> void
    {
        c.push_back(x);
    }

    /// \brief Pushes the given element value to the top of the stack.
    constexpr auto push(value_type&& x) noexcept(
        noexcept(declval<container_type>().push_back(move(x)))) -> void
    {
        c.push_back(move(x));
    }

    /// \brief Pushes a new element on top of the stack. The element is
    /// constructed in-place, i.e. no copy or move operations are performed. The
    /// constructor of the element is called with exactly the same arguments as
    /// supplied to the function.
    template <typename... Args>
    constexpr auto emplace(Args&&... args) noexcept(noexcept(
        declval<container_type>().emplace_back(forward<Args>(args)...)))
        -> decltype(auto)
    {
        return c.emplace_back(forward<Args>(args)...);
    }

    /// \brief Removes the top element from the stack.
    /// \complexity Equal to the complexity of Container::pop_back.
    constexpr auto pop() noexcept(
        noexcept(declval<container_type>().pop_back())) -> void
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
/// is_swappable<Container>::value is true.
template <typename T, typename Container,
    TETL_REQUIRES_(is_swappable_v<Container>)>
constexpr auto swap(stack<T, Container>& lhs,
    stack<T, Container>& rhs) noexcept(noexcept(lhs.swap(rhs))) -> void
{
    lhs.swap(rhs);
}

} // namespace etl

#endif // TETL_STACK_HPP