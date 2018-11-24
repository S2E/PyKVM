PyKVM - A KVM client written in Python
======================================

PyKVM a small KVM client that demonstrates how to use the Kernel-based Virtual Machine (KVM) interface from Python. The
client first initializes a barebones VM with a small amount of memory, and then loads and runs a raw binary. Since there
is no guest OS, no devices, and no I/O available, all the binary can do is access CPU registers and memory.

This client is compatible with the `KVM extensions for symbolic execution
<http://s2e.systems/docs/DesignAndImplementation/KvmInterface.html>`__ provided by `S2E <https://s2e.systems>`__. In
other words, you can symbolically execute programs with PyKVM.

Running with native KVM
-----------------------

First, build the sample binary. This binary writes 4KB of data at address ``0x1000`` and then halts the CPU.

.. code:: sh

        git clone https://github.com/s2e/pykvm
        cd pykvm
        make -C sample

Then, run the compiled ``sample.bin`` binary in PyKVM. Make sure that ``/dev/kvm`` is accessible.

.. code:: sh

        python -m pykvm.kvm sample/sample.bin

The output will show the state of the memory before and after executing the binary.


Symbolic execution
------------------

We will now swap native KVM for a version that implements symbolic execution.

First, you need to build S2E. Please refer to the S2E `documentation <http://s2e.systems/docs>`__ for more details. In
all the commands below, the ``S2EDIR`` variables points to the root of your S2E environment set up using `s2e-env
<http://s2e.systems/docs/s2e-env.html>`__.

Second, recompile the sample binary with S2E support. This is necessary in order to write symbolic values to memory. At
the moment, PyKVM cannot write symbolic data to memory directly, so it must be done from the running binary
instead.

.. code:: sh

        make -C sample clean
        make -C sample EXTRA_CFLAGS="-DUSE_S2E -I$S2EDIR/source/s2e/guest/common/include"

        export S2E_CONFIG=sample/s2e-config.lua

        # libs2e.so uses LD_PRELOAD to intercept all calls to /dev/kvm in order to emulate
        # native KVM while at the same time providing symbolic execution capabilities.
        LD_PRELOAD=$S2EDIR/build/s2e/libs2e-release/x86_64-s2e-softmmu/libs2e.so python -m pykvm.kvm sample/sample.bin

When all the paths complete, ``libs2e`` automatically terminates the Python process. You can inspect
``s2e-last/debug.txt`` to see symbolic execution output. You will find several test cases corresponding to various
execution paths of the sample binary. Please refer to the sample binary's source code for more details about the
expected results.

Projects
--------

Here are some of the interesting things you could try and build on top of PyKVM.

1. Run PyKVM in GDB together with ``libs2e``. The ``gdb.ini`` script contains the required configuration for S2E. Do not
   forget to adapt the paths in there to your system.

   .. code:: sh

        gdb --init-command gdb.ini --args python -m pykvm.kvm sample/sample.bin

2. Write a small library that implements an ``s2e_make_symbolic`` syscall, so that binaries can get symbolic data
   easier. You can view this library as an OS, or better yet the BIOS.

3. Extend PyKVM to load actual ELF/PE files into memory. Of course, they won't have any imports or OS dependencies.
