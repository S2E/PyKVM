# Copyright (c) 2018, Cyberhaven
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


quiet-command = $(if $(V),$1,$(if $(2),@echo $2 && $1, @$1))

LD_SCRIPT = 32.ld

CFLAGS = -std=c99 -O3 -g -ffreestanding  -nostdlib -fno-omit-frame-pointer -mno-red-zone
CFLAGS += -fno-exceptions -fno-asynchronous-unwind-tables -m32 $(EXTRA_CFLAGS)

.PHONY : all clean

%.o: %.c
	$(call quiet-command,$(CC) $(CFLAGS) -c -o $@ $^,"  Building $@")

sample.bin: sample
	objcopy -O binary --rename-section .data=.rodata,alloc,load,data,contents,readonly $^ $@

sample: sample.o
	$(LD) -T $(LD_SCRIPT)  -o $@ $^

clean:
	rm -f sample.bin sample.o sample

all: sample.bin
