set(MCU -mcpu=cortex-m7 -mthumb -mfloat-abi=hard -mfpu=fpv5-d16)
add_compile_options(${MCU})
add_link_options(${MCU})
