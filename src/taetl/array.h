/*
Copyright (c) 2019, Tobias Hienzsch
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
*/

#ifndef TAETL_ARRAY_H
#define TAETL_ARRAY_H

// TAETL
#include "definitions.h"

namespace taetl
{
template <class Type, uint32_t Size> class Array
{
private:
    uint32_t _size{};
    uint32_t _capacity{Size};
    Type _data[Size];

public:
    typedef Type value_type;
    typedef Type* pointer;
    typedef const Type* const_pointer;
    typedef Type& reference;
    typedef const Type& const_reference;
    typedef Type* iterator;
    typedef const Type* const_iterator;

    iterator begin() TAETL_NOEXCEPT;
    const_iterator cbegin() const TAETL_NOEXCEPT;

    iterator end() TAETL_NOEXCEPT;
    const_iterator cend() const TAETL_NOEXCEPT;

    reference front();
    reference back();

    void push_back(const Type& value);
    void pop_back();

    bool empty() const TAETL_NOEXCEPT;
    uint32_t size() const TAETL_NOEXCEPT;
    uint32_t capacity() const TAETL_NOEXCEPT { return _capacity; }

    Type& operator[](uint32_t index);
    void clear();
};

template <class Type, uint32_t Size> typename Array<Type, Size>::iterator Array<Type, Size>::begin() TAETL_NOEXCEPT
{
    return _data;
}

template <class Type, uint32_t Size> typename Array<Type, Size>::iterator Array<Type, Size>::end() TAETL_NOEXCEPT
{
    return _data + size();
}

template <class Type, uint32_t Size>
typename Array<Type, Size>::const_iterator Array<Type, Size>::cbegin() const TAETL_NOEXCEPT
{
    return _data;
}

template <class Type, uint32_t Size>
typename Array<Type, Size>::const_iterator Array<Type, Size>::cend() const TAETL_NOEXCEPT
{
    return _data + size();
}

template <class Type, uint32_t Size> typename Array<Type, Size>::reference Array<Type, Size>::front()
{
    return _data[0];
}

template <class Type, uint32_t Size> typename Array<Type, Size>::reference Array<Type, Size>::back()
{
    return _data[_size - 1];
}

template <class Type, uint32_t Size> void Array<Type, Size>::push_back(const Type& v)
{
    if (_size >= _capacity)
    {
        return;
    }

    _data[_size++] = v;
}

template <class Type, uint32_t Size> void Array<Type, Size>::pop_back() { _size--; }

template <class Type, uint32_t Size> bool Array<Type, Size>::empty() const TAETL_NOEXCEPT
{
    if (_size == 0)
    {
        return true;
    }

    return false;
}

template <class Type, uint32_t Size> uint32_t Array<Type, Size>::size() const TAETL_NOEXCEPT { return _size; }

template <class Type, uint32_t Size> Type& Array<Type, Size>::operator[](uint32_t index) { return _data[index]; }

template <class Type, uint32_t Size> void Array<Type, Size>::clear() { _size = 0; }
}  // namespace taetl
#endif  // TAETL_ARRAY_H