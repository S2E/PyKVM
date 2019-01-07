// Copyright (c) 2018, Cyberhaven
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.


#include <inttypes.h>

#ifdef USE_S2E
#include <s2e/s2e.h>
#endif

#define DATA_START 0x1000
#define DATA_SIZE 0x1000

// This is a sample application that demonstrates the use of the PyKVM.
// It is composed of only one function that will be compiled to a raw binary
// file that can be directly loaded in memory and executed.
//
// Notes:
// - The main function must really come first, that's where execution starts.
//   If you want to add more functions, make sure the linker places them after main().
// - It expects the stack pointer to be properly initialized
// - It expects to be loaded at address 0 in memory
// - It claims a 4KB range starting at address 0x1000 as scratch data
// - There is no standard library
// - I/O is not possible (as PyKVM does not implement it)
void main(void)
{
    uint8_t *data = (uint8_t*) DATA_START;

    // Fill the memory with a random pattern
    for (unsigned i = 0; i < DATA_SIZE; ++i) {
        data[i] = i;
    }

    // Add EXTRA_CFLAGS="-DUSE_S2E -I/path/to/s2e/include" if you want to run this binary
    // in PyKVM using symbolic execution.
    #ifdef USE_S2E
    s2e_make_concolic(data, 1, "mydata");
    if (data[0] == 1) {
        // You should see the message true/false appear in s2e-last/debug.txt together with the concrete
        // value of the symbolic variable mydata.
        s2e_kill_state(1, "true");
    } else {
        s2e_kill_state(0, "false");
    }
    #endif

    // Returning from this function will behave unpredictably, most likely causing
    // a crash of the VM. So we use the halt instruction instead, to indicate that we are done.
    __asm__("hlt");
}
