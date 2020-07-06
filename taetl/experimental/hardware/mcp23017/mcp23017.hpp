/*
Copyright (c) 2019-2020, Tobias Hienzsch
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

#ifndef TAETL_HARDWARE_MCP23017_MCP23017_HPP
#define TAETL_HARDWARE_MCP23017_MCP23017_HPP

#include "taetl/definitions.hpp"
#include "taetl/warning.hpp"

namespace taetl::hardware::mcp23017
{
// ports
enum class port : taetl::uint16_t
{
    a = 0x00,
    b = 0x01,
};

// Address (A0-A2)
enum class address : taetl::uint16_t
{
    a20 = 0x20,
    a21 = 0x21,
    a22 = 0x22,
    a23 = 0x23,
    a24 = 0x24,
    a25 = 0x25,
    a26 = 0x26,
    a27 = 0x27,
};

// registers
enum class registers : taetl::uint16_t
{
    io_direction_a = 0x00,  // datasheet: IODIRA
    io_direction_b = 0x01,  // datasheet: IODIRB
    IPOLA          = 0x02,
    IPOLB          = 0x03,
    GPINTENA       = 0x04,
    GPINTENB       = 0x05,
    DEFVALA        = 0x06,
    DEFVALB        = 0x07,
    INTCONA        = 0x08,
    INTCONB        = 0x09,
    //	IOCON			0x0A
    //	IOCON			0x0B
    GPPUA   = 0x0C,
    GPPUB   = 0x0D,
    INTFA   = 0x0E,
    INTFB   = 0x0F,
    INTCAPA = 0x10,
    INTCAPB = 0x11,
    GPIOA   = 0x12,
    GPIOB   = 0x13,
    OLATA   = 0x14,
    OLATB   = 0x15,
};

// I/O Direction
// Default state: io_direction::all_output
enum class io_direction : taetl::uint8_t
{
    all_output = 0x00,
    all_input  = 0xFF,
    input_O0   = 0x01,
    input_O1   = 0x02,
    input_O2   = 0x04,
    input_O3   = 0x08,
    input_O4   = 0x10,
    input_O5   = 0x20,
    input_O6   = 0x40,
    input_O7   = 0x80,
};

// Input Polarity
// Default state: MCP23017_IPOL_ALL_NORMAL
enum class io_polarity : taetl::uint8_t
{
    all_normal   = 0x00,
    all_inverted = 0xFF,
    inverted_O0  = 0x01,
    inverted_O1  = 0x02,
    inverted_O2  = 0x04,
    inverted_O3  = 0x08,
    inverted_O4  = 0x10,
    inverted_O5  = 0x20,
    inverted_O6  = 0x40,
    inverted_O7  = 0x80,
};

// Pull-Up Resistor
// Default state: MCP23017_GPPU_ALL_DISABLED
enum class pull_up_resistor : taetl::uint8_t
{
    all_disabled = 0x00,
    all_enabled  = 0xFF,
    enabled_O0   = 0x01,
    enabled_O1   = 0x02,
    enabled_O2   = 0x04,
    enabled_O3   = 0x08,
    enabled_O4   = 0x10,
    enabled_O5   = 0x20,
    enabled_O6   = 0x40,
    enabled_O7   = 0x80,
};

template <typename Driver>
class device
{
public:
    explicit device()     = default;
    ~device()             = default;
    device(device&&)      = delete;
    device(device const&) = delete;
    auto operator=(device&&) -> device& = delete;
    auto operator=(device const&) -> device& = delete;

    auto init() -> bool { return true; }
    auto set_io_direction(port p, io_direction direction) -> void
    {
        taetl::ignore_unused(p, direction);
    }
};
}  // namespace taetl::hardware::mcp23017

#endif  // TAETL_HARDWARE_MCP23017_MCP23017_HPP
