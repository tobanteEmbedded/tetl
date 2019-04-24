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
template <class Type, taetl::size_t Size>
class Array
{
private:
    taetl::size_t _size{};
    taetl::size_t _capacity{Size};
    Type _data[Size];

public:
    typedef Type value_type;
    typedef Type* pointer;
    typedef const Type* const_pointer;
    typedef Type& reference;
    typedef const Type& const_reference;
    typedef Type* iterator;
    typedef const Type* const_iterator;

    iterator begin() TAETL_NOEXCEPT { return _data; }
    const_iterator cbegin() const TAETL_NOEXCEPT { return _data; }

    iterator end() TAETL_NOEXCEPT { return _data + size(); }
    const_iterator cend() const TAETL_NOEXCEPT { return _data + size(); }

    reference front() { return _data[0]; }
    reference back() { return _data[_size - 1]; }

    void push_back(const Type& value)
    {
        if (_size >= _capacity)
        {
            return;
        }

        _data[_size++] = value;
    }

    void pop_back() { _size--; }

    bool empty() const TAETL_NOEXCEPT
    {
        if (_size == 0)
        {
            return true;
        }

        return false;
    }

    taetl::size_t size() const TAETL_NOEXCEPT { return _size; }
    taetl::size_t capacity() const TAETL_NOEXCEPT { return _capacity; }

    Type& operator[](taetl::size_t index) { return _data[index]; }

    void clear() { _size = 0; }
};

}  // namespace taetl

#endif  // TAETL_ARRAY_H