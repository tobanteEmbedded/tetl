.PHONY: default
default: all

include make/common.mk

ifndef CLANG
	include make/gcc.mk
else
	include make/clang.mk
endif 

MODULES += src/main
MODULES += src/sysmem
MODULES += src/system_stm32f1xx
MODULES += src/syscalls
MODULES += src/startup_stm32f103c8tx

OBJS = $(addsuffix .o, $(MODULES))


BINDIR	= bin/
# OBJDIR	= obj/
# SRCDIR	= src/

# final executable name
_BIN	= firmware
BIN		= $(addprefix $(BINDIR), $(_BIN))
FIRMWARE_ELF = $(BIN).elf
FIRMWARE_BIN = $(BIN).bin


.PHONY: all
all: $(BINDIR) $(FIRMWARE_BIN) size


%.o: %.s
	@echo "$<"
	@$(AS) -c $(COMMONFLAGS) -x assembler-with-cpp -D__ASSEMBLY__ -c -o $@ $<

%.o: %.c
	@echo "$<"
	@$(CC) -c $(CFLAGS) $(DEFINES) $(INCLUDES) -c -o $@ $<

%.o: %.cpp
	@echo "$<"
	@$(CXX) -c $(CXXFLAGS) $(DEFINES) $(INCLUDES) -c -o $@ $<

$(BINDIR):
	@mkdir -p $(BINDIR)

$(FIRMWARE_ELF): $(OBJS)
	@$(LD) -o $@ $? $(LDFLAGS)

$(FIRMWARE_BIN): $(FIRMWARE_ELF)
	@$(OBJCOPY) -O binary $? $@

.PHONY: size
size: $(FIRMWARE_ELF)
	@$(SIZE) -B $(FIRMWARE_ELF)

.PHONY: upload
upload: $(FIRMWARE_BIN)
	st-flash --reset write $(FIRMWARE_BIN) 0x08000000
	
.PHONY: clean
clean:
	find . -name "*.d" -type f -delete
	find . -name "*.o" -type f -delete
	find . -name "*.su" -type f -delete
	find . -name "*.map" -type f -delete
	find . -name "*.elf" -type f -delete
	rm -rf bin/ obj/

.PHONY: format
format:
	find include -iname '*.hpp' -o -iname '*.cpp' -o -iname '*.h' -o -iname '*.c' | xargs clang-format -i
	find src -iname '*.hpp' -o -iname '*.cpp' -o -iname '*.h' -o -iname '*.c' | xargs clang-format -i

.PHONY: toolchain
toolchain:
	@echo "Root: $(TOOLCHAIN_ROOT)"
	@echo "Version: $(TOOLCHAIN_VERSION)"