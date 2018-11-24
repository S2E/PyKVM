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

import array
import errno
import fcntl
import logging
import mmap
import os
from argparse import ArgumentParser

import ctypes
from ctypes import c_int, c_size_t, c_void_p
from ctypes.util import find_library as ctypes_find_library

from hexdump import hexdump

# We use most of the classes from there, importing one by one is too tedious
# pylint: disable=unused-wildcard-import
# pylint: disable=wildcard-import
from pykvm.kvm_types import *

logger = logging.getLogger(__name__)

libc = ctypes.cdll.LoadLibrary(ctypes_find_library('c'))
libc.mmap.argtypes = [c_void_p, c_size_t, c_int, c_int, c_size_t]
libc.mmap.restype = c_void_p


MAP_FAILED = 0xffffffffffffffff


class RAM(object):
    def __init__(self, size, vm):
        if size % 0x1000:
            raise RuntimeError('Ram size must be a multiple of 4KB')

        self._size = size
        self._vm = vm

        # TODO: deallocate memory on exit
        logger.debug('Allocating %d bytes for RAM', size)
        self._pointer = libc.mmap(-1, self._size, mmap.PROT_READ | mmap.PROT_WRITE,
                                  mmap.MAP_ANON | mmap.MAP_PRIVATE, -1, 0)

        if self._pointer == MAP_FAILED or not self._pointer:
            raise RuntimeError('Could not allocate buffer of size %#x' % size)

        logger.debug('RAM is at %#lx', self._pointer)
        self.obj = (ctypes.c_ubyte * size).from_address(self._pointer)

    def get_kvm_region(self, slot):
        ram = KVMUserSpaceMemoryRegion()
        ram.slot = slot
        ram.flags = 0
        ram.guest_phys_addr = 0
        ram.memory_size = self._size
        ram.userspace_addr = self._pointer
        return ram

    def write(self, addr, data):
        if addr + len(data) > self._size:
            raise RuntimeError('Buffer overflow')

        if self._vm.has_mem_rw:
            b = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
            m = KVMMemRW()
            m.source = ctypes.addressof(b)
            m.dest = self._pointer + addr
            m.is_write = 1
            m.length = len(data)
            logger.debug('Writing to %#lx from %#lx, size=%#lx', m.dest, m.source, m.length)
            fcntl.ioctl(self._vm.fd, KVM_MEM_RW, m)
        else:
            for i, c in enumerate(data):
                self.obj[addr + i] = ord(c)

    def read(self, addr, size):
        if addr + size > self._size:
            raise RuntimeError('Buffer overflow')

        if self._vm.has_mem_rw:
            ret = (ctypes.c_ubyte * size)()
            m = KVMMemRW()
            m.source = self._pointer + addr
            m.dest = ctypes.addressof(ret)
            m.is_write = 0
            m.length = size
            fcntl.ioctl(self._vm.fd, KVM_MEM_RW, m)
        else:
            ret = self.obj[addr:addr+size]

        return array.array('B', ret).tostring()


def _get_32bit_code_segment():
    """
    Refer to the Intel System Developer Manual (Vol 3) for details
    about the meaning of these fields.

    :return: A code segment suitable for executing 32-bit binaries
    """

    s = KVMSegment()

    s.base = 0
    s.limit = 0xffffffff
    s.selector = 0
    s.type = 0xc  # Execute / Read
    s.present = 1
    s.dpl = 0
    s.db = 1
    s.s = 1
    s.l = 0
    s.g = 1

    return s


def _get_32bit_data_segment():
    """
    Refer to the Intel System Developer Manual (Vol 3) for details
    about the meaning of these fields.

    :return: A data segment suitable for executing 32-bit binaries
    """

    s = KVMSegment()

    s.base = 0
    s.limit = 0xffffffff
    s.selector = 0
    s.type = 0x2  # Read / Write
    s.present = 1
    s.dpl = 0
    s.db = 1
    s.s = 1
    s.l = 0
    s.g = 1

    return s


# TODO: clean up all resources
class VCPU(object):
    def __init__(self, kvm_fd, vm_fd):
        self._vm_fd = vm_fd

        self._vcpu_fd = fcntl.ioctl(vm_fd, KVM_CREATE_VCPU)
        logger.debug('Created VCPU fd=%d', self._vcpu_fd)

        self._vcpu_size = fcntl.ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE)
        logger.debug('VCPU requires %d bytes for kvm_run structure', self._vcpu_size)

        # Note: use mmap.mmap instead of libc.mmap because the later can't be intercepted
        # by the libs2e shim library (probably due to how ctypes resolves library functions).
        self._pointer = mmap.mmap(self._vcpu_fd, self._vcpu_size)
        self._run_obj = KVMRun.from_buffer(self._pointer)

    def init_state(self, rip=0, rsp=0, bits=32):
        sregs = KVMSRegs()
        fcntl.ioctl(self._vcpu_fd, KVM_GET_SREGS, sregs)

        if bits == 16:
            sregs.cs.base = 0
            sregs.cs.selector = 0
        elif bits == 32:
            # Initialize the bare minimum. We just initialize the shadow part of the segments registers.
            # It is not necessary to set up the GDT/IDT/LDT as long as the guest does not modify segment registers
            # and there are no interrupts (hardware or software).
            sregs.cs = _get_32bit_code_segment()
            sregs.ds = _get_32bit_data_segment()
            sregs.es = sregs.ds
            sregs.ss = sregs.ds
            sregs.fs = sregs.ds
            sregs.gs = sregs.ds

            # Enable protected mode
            sregs.cr0 = 0x1
        else:
            raise ValueError('Unsupported number of bits %d' % bits)

        fcntl.ioctl(self._vcpu_fd, KVM_SET_SREGS, sregs)

        regs = KVMRegs()
        fcntl.ioctl(self._vcpu_fd, KVM_GET_REGS, regs)
        regs.rip = rip
        regs.rsp = rsp
        regs.rflags = 2
        fcntl.ioctl(self._vcpu_fd, KVM_SET_REGS, regs)

    def dump_regs(self):
        """
        Displays the content of guest CPU registers.
        """

        regs = KVMRegs()
        fcntl.ioctl(self._vcpu_fd, KVM_GET_REGS, regs)
        logger.info('rax=%#lx rbx=%#lx rcx=%#lx rdx=%#lx', regs.rax, regs.rbx, regs.rcx, regs.rdx)
        logger.info('rsi=%#lx rdi=%#lx rbp=%#lx rsp=%#lx', regs.rsi, regs.rdi, regs.rbp, regs.rsp)
        logger.info('rip=%#lx', regs.rip)

    # pylint: disable=too-many-branches
    def run(self):
        """
        Runs the virtual machine until an exit condition occurs.
        One way to terminate execution is for the guest to execute the HLT instruction.
        We don't support I/O, MMIO, and some other cases, so this function will terminate when it encounters them.
        """

        logger.info('Running KVM')

        while True:
            try:
                fcntl.ioctl(self._vcpu_fd, KVM_RUN)
            except IOError as e:
                if e.errno != errno.EINTR:
                    raise

            reason = KVMExitReason(self._run_obj.exit_reason)

            if reason == KVMExitReason.KVM_EXIT_INTERNAL_ERROR:
                # KVM encountered an internal fault. This usually happens when the guest tries
                # to execute some garbage (triple faults, reboots, invalid instructions, etc.).
                raise RuntimeError(KVMInternalError(self._run_obj.exit_reasons.internal.suberror))
            elif reason == KVMExitReason.KVM_EXIT_IO:
                # Triggered when the guest executes an IO instruction (e.g., inp, outb on x86)
                # These I/O ports belong to virtual devices. We terminate execution when this happens as
                # we don't support virtual devices yet.
                logger.info('%s %s', reason, self._run_obj.exit_reasons.io)
                break
            elif reason == KVMExitReason.KVM_EXIT_MMIO:
                # An MMIO exit event is triggered when the guest accesses unmapped physical memory.
                # This memory typically belongs to virtual devices. We terminate execution when this happens as
                # we don't support virtual devices yet.
                logger.info('%s %s', reason, self._run_obj.exit_reasons.mmio)
                break
            elif reason == KVMExitReason.KVM_EXIT_HLT:
                # This hypervisor uses the hlt instruction as an indication that the binary has finished running.
                logger.info('CPU halted, exiting (%s)', reason)
                break
            elif reason == KVMExitReason.KVM_EXIT_SHUTDOWN:
                logger.info('Shutting down')
                break
            elif reason == KVMExitReason.KVM_EXIT_INTR:
                # Something interrupted the KVM server, just resume execution
                pass
            elif reason == KVMExitReason.KVM_EXIT_FLUSH_DISK:
                # We don't need to implement this, as we have no disk
                pass
            elif reason == KVMExitReason.KVM_EXIT_SAVE_DEV_STATE:
                # We don't have any device state to save for symbolic execution
                pass
            elif reason == KVMExitReason.KVM_EXIT_RESTORE_DEV_STATE:
                # We don't have any device state to restore for symbolic execution
                pass
            elif reason == KVMExitReason.KVM_EXIT_CLONE_PROCESS:
                raise RuntimeError('Multi-core mode not supported')
            else:
                raise RuntimeError('Unhandled exit code %s' % reason)


def has_capability(kvm_fd, cap):
    """
    Determines if the KVM implementation has the requested capability.
    :return A non-zero value if the capability is supported.
    """
    ret = 0

    try:
        ret = fcntl.ioctl(kvm_fd, KVM_CHECK_EXTENSION, cap)
    except Exception:
        logger.debug('KVM_CHECK_EXTENSION failed')
    finally:
        logger.info('%s: %d', cap, ret)

    return ret


class VM(object):
    """
    This class represents a VM, composed of some guest RAM and one CPU.
    The user of this class is responsible for providing a file descriptor to /dev/kvm.
    """

    def __init__(self, kvm_fd, ram_size):
        self.has_mem_fixed_region = has_capability(kvm_fd, KVMCapability.KVM_CAP_MEM_FIXED_REGION)
        self.has_mem_rw = has_capability(kvm_fd, KVMCapability.KVM_CAP_MEM_RW)

        self._vm_fd = fcntl.ioctl(kvm_fd, KVM_CREATE_VM)
        self._ram = RAM(ram_size, self)
        kvm_region = self._ram.get_kvm_region(0)

        if self.has_mem_fixed_region:
            fixed_region = KVMFixedRegion()
            fixed_region.name = 'ram'
            fixed_region.host_address = kvm_region.userspace_addr
            fixed_region.size = kvm_region.memory_size
            fixed_region.flags = 0

            fcntl.ioctl(self._vm_fd, KVM_MEM_REGISTER_FIXED_REGION, fixed_region)

        fcntl.ioctl(self._vm_fd, KVM_SET_USER_MEMORY_REGION, kvm_region)

        self._vcpu = VCPU(kvm_fd, self._vm_fd)
        self._vcpu.init_state()

    def run(self):
        """
        Run the VM. See documentation in the VCPU class for details.
        """
        self._vcpu.run()

    @property
    def ram(self):
        return self._ram

    @property
    def vcpu(self):
        return self._vcpu

    @property
    def fd(self):
        return self._vm_fd


def main():
    """
    This is a demo of the Python KVM APIs.
    It creates a virtual machine, loads the specified binary, then runs it.
    The VM starts in protected mode, no paging, 32-bit.

    The binary must be raw, i.e., just instructions and data, without any headers.
    When it is done running, it must execute the HLT instruction, otherwise the VM may
    execute garbage past the last instruction.

    The binary cannot do any I/O or otherwise interact with the outside world. There are no devices.
    Everything happens in memory.
    """

    logging.basicConfig(level=logging.DEBUG)
    logger.setLevel('DEBUG')

    # TODO: make log level configurable
    parser = ArgumentParser()
    parser.add_argument('--memsize', type=lambda x: int(x, 0), default=0x20000, help='Size of guest memory in bytes')
    parser.add_argument('--rip', type=lambda x: int(x, 0), default=0x0, help='Initial program counter')
    parser.add_argument('--rsp', type=lambda x: int(x, 0), default=0xfff0, help='Initial stack pointer')
    parser.add_argument('--org', type=lambda x: int(x, 0), default=0x0, help='Load base of the binary')
    parser.add_argument('--dump', type=lambda x: int(x, 0), default=0x1000, help='Address to dump when complete')
    parser.add_argument('--dump-size', type=lambda x: int(x, 0), default=0x100, help='How many bytes to dump')
    parser.add_argument('binary', nargs=1, help='Raw binary file to load and execute (32-bit x86)')
    args = parser.parse_args()

    if not os.path.exists(args.binary[0]):
        logger.error('%s does not exist', args.binary[0])
        return

    # Must use open for libs2e, as it does not intercept fopen()
    fp = os.open('/dev/kvm', os.O_RDWR)
    api_version = fcntl.ioctl(fp, KVM_GET_API_VERSION)
    logging.info('KVM API version: %d', api_version)

    vm = VM(fp, args.memsize)
    vm.vcpu.init_state(rip=args.rip, rsp=args.rsp, bits=32)

    # Load the input binary into memory
    with open(args.binary[0], 'rb') as fp:
        logger.info('Writing binary to offset %#x', args.org)
        vm.ram.write(args.org, fp.read())

    logger.info('Binary before execution')
    hexdump(vm.ram.read(args.org, 0x100))

    vm.run()

    vm.vcpu.dump_regs()

    logger.info('Dumping address %#lx of size %#lx', args.dump, args.dump_size)
    hexdump(vm.ram.read(args.dump, args.dump_size))


if __name__ == "__main__":
    main()
