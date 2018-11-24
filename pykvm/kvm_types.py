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

from ctypes import Structure, Union, c_uint8, c_uint16, c_uint32, c_uint64, c_char_p
from enum import IntEnum

from ioctl_opt import IO, IOW, IOR


class KVMUserSpaceMemoryRegion(Structure):
    _fields_ = [
        ('slot', c_uint32),
        ('flags', c_uint32),
        ('guest_phys_addr', c_uint64),
        ('memory_size', c_uint64),
        ('userspace_addr', c_uint64)
    ]


class KVMRegs(Structure):
    _fields_ = [
        ('rax', c_uint64),
        ('rbx', c_uint64),
        ('rcx', c_uint64),
        ('rdx', c_uint64),
        ('rsi', c_uint64),
        ('rdi', c_uint64),
        ('rsp', c_uint64),
        ('rbp', c_uint64),
        ('r8', c_uint64),
        ('r9', c_uint64),
        ('r10', c_uint64),
        ('r11', c_uint64),
        ('r12', c_uint64),
        ('r13', c_uint64),
        ('r14', c_uint64),
        ('r15', c_uint64),
        ('rip', c_uint64),
        ('rflags', c_uint64),
    ]


class KVMSegment(Structure):
    _fields_ = [
        ('base', c_uint64),
        ('limit', c_uint32),
        ('selector', c_uint16),
        ('type', c_uint8),
        ('present', c_uint8),
        ('dpl', c_uint8),

        # Default operation size (1 = 32bit, 0 = 16bit)
        ('db', c_uint8),

        # 0 = system segment, 1 = data/code segment
        ('s', c_uint8),

        # 1 = 64-bit
        ('l', c_uint8),

        # Granularity, 1 = 4KB, 0 = 1 byte
        ('g', c_uint8),
        ('avl', c_uint8),
        ('unusable', c_uint8),
        ('padding', c_uint8),
    ]


class KVMDTable(Structure):
    _fields_ = [
        ('base', c_uint64),
        ('limit', c_uint16),
        ('padding', c_uint16 * 3),
    ]


KVM_NR_INTERRUPTS = 256


class KVMSRegs(Structure):
    _fields_ = [
        ('cs', KVMSegment),
        ('ds', KVMSegment),
        ('es', KVMSegment),
        ('fs', KVMSegment),
        ('gs', KVMSegment),
        ('ss', KVMSegment),

        ('tr', KVMSegment),
        ('ldt', KVMSegment),

        ('gdt', KVMDTable),
        ('idt', KVMDTable),

        ('cr0', c_uint64),
        ('cr2', c_uint64),
        ('cr3', c_uint64),
        ('cr4', c_uint64),
        ('cr8', c_uint64),

        ('efer', c_uint64),
        ('apic_base', c_uint64),
        ('interrupt_bitmap', c_uint64 * ((KVM_NR_INTERRUPTS + 63) / 64)),
    ]


class KVMInternalError(IntEnum):
    KVM_INTERNAL_ERROR_EMULATION = 1
    KVM_INTERNAL_ERROR_SIMUL_EX = 2
    KVM_INTERNAL_ERROR_DELIVERY_EV = 3


class KVMExitReason(IntEnum):
    KVM_EXIT_UNKNOWN = 0
    KVM_EXIT_EXCEPTION = 1
    KVM_EXIT_IO = 2
    KVM_EXIT_HYPERCALL = 3
    KVM_EXIT_DEBUG = 4
    KVM_EXIT_HLT = 5
    KVM_EXIT_MMIO = 6
    KVM_EXIT_IRQ_WINDOW_OPEN = 7
    KVM_EXIT_SHUTDOWN = 8
    KVM_EXIT_FAIL_ENTRY = 9
    KVM_EXIT_INTR = 10
    KVM_EXIT_SET_TPR = 11
    KVM_EXIT_TPR_ACCESS = 12
    KVM_EXIT_S390_SIEIC = 13
    KVM_EXIT_S390_RESET = 14
    KVM_EXIT_DCR = 15
    KVM_EXIT_NMI = 16
    KVM_EXIT_INTERNAL_ERROR = 17
    KVM_EXIT_OSI = 18
    KVM_EXIT_PAPR_HCALL = 19
    KVM_EXIT_S390_UCONTROL = 20
    KVM_EXIT_WATCHDOG = 21
    KVM_EXIT_S390_TSCH = 22
    KVM_EXIT_EPR = 23
    KVM_EXIT_SYSTEM_EVENT = 24

    #########################################
    # Symbolic execution exit codes

    # The symbolic execution engine wants the client to flush the disk.
    # Implementing this is not required if the client does not implement virtual disks.
    KVM_EXIT_FLUSH_DISK = 100

    # The symbolic execution engine wants the client to save/restore a snapshot of device states.
    # Implementing this is not required if the client does not have device state.
    KVM_EXIT_SAVE_DEV_STATE = 101
    KVM_EXIT_RESTORE_DEV_STATE = 102

    # The symbolic execution engine has forked the process and requests the client to update
    # its internal data structures, recreate threads, etc.
    KVM_EXIT_CLONE_PROCESS = 103


class KVMCapability(IntEnum):
    # TODO: add generic KVM capabilities
    # ...

    # The following capabilities are specific to libs2e.
    # They are required for multi-path symbolic execution support.
    # More details on http://s2e.systems.
    KVM_CAP_MEM_FIXED_REGION = 256
    KVM_CAP_MEM_RW = 1021
    KVM_CAP_DISK_RW = 257

    KVM_CAP_DBT = 259
    KVM_CAP_CPU_CLOCK_SCALE = 1022
    KVM_CAP_FORCE_EXIT = 255
    KVM_CAP_DEV_SNAPSHOT = 259


class KVMRunExitMMIO(Structure):
    _fields_ = [
        ('phys_addr', c_uint64),
        ('data', c_uint8 * 8),
        ('len', c_uint32),
        ('is_write', c_uint8),
    ]

    def __str__(self):
        return 'phys_addr = %#lx len = %#x is_write = %d' % (
            self.phys_addr, self.len, self.is_write
        )


class KVMRunExitIO(Structure):
    _fields_ = [
        ('direction', c_uint8),
        ('size', c_uint8),
        ('port', c_uint16),
        ('count', c_uint32),
        ('data_offset', c_uint64),
    ]

    def __str__(self):
        return 'direction = %d size = %d port = %#x count = %#x, data_offset = %#x' % (
            self.direction, self.size, self.port, self.count, self.data_offset
        )


class KVMRunExitInternal(Structure):
    _fields_ = [
        ('suberror', c_uint32),
        ('ndata', c_uint32),
        ('data', c_uint64 * 16),
    ]


class KVMRunExitUnknown(Structure):
    _fields_ = [
        ('hardware_exit_reason', c_uint64)
    ]


class KVMRunExitReasons(Union):
    _fields_ = [
        ('hw', KVMRunExitUnknown),
        ('internal', KVMRunExitInternal),
        ('io', KVMRunExitIO),
        ('mmio', KVMRunExitMMIO),
    ]


class KVMRun(Structure):
    _fields_ = [
        # Input
        ('request_interrupt_window', c_uint8),
        ('padding1', c_uint8 * 7),

        # Output
        ('exit_reason', c_uint32),
        ('ready_for_interrupt_injection', c_uint8),
        ('if_flag', c_uint8),
        ('padding1', c_uint8 * 2),

        # in (pre_KVMRun), out (post_KVMRun)
        ('cr8', c_uint64),
        ('apic_base', c_uint64),

        ('exit_reasons', KVMRunExitReasons)
    ]


KVMIO = 0xae

# KVM IOCTLs
KVM_GET_API_VERSION = IO(KVMIO, 0x00)
KVM_CREATE_VM = IO(KVMIO, 0x01)
KVM_CHECK_EXTENSION = IO(KVMIO, 0x03)
KVM_GET_VCPU_MMAP_SIZE = IO(KVMIO, 0x04)

# KVM VM IOCTLs
KVM_CREATE_VCPU = IO(KVMIO, 0x41)
KVM_SET_TSS_ADDR = IO(KVMIO, 0x47)
KVM_SET_USER_MEMORY_REGION = IOW(KVMIO, 0x46, KVMUserSpaceMemoryRegion)

# KVM CPU IOCTLs
KVM_RUN = IO(KVMIO, 0x80)

KVM_GET_REGS = IOR(KVMIO, 0x81, KVMRegs)
KVM_SET_REGS = IOW(KVMIO, 0x82, KVMRegs)
KVM_GET_SREGS = IOR(KVMIO, 0x83, KVMSRegs)
KVM_SET_SREGS = IOW(KVMIO, 0x84, KVMSRegs)

#########################################################################################
# The KVM structures and APIs below are not part of the standard KVM interface.
# They are part of the KVM extensions for symbolic execution by S2E (http://s2e.systems).


# Available with KVM_CAP_MEM_FIXED_REGION
class KVMFixedRegion(Structure):
    _fields_ = [
        ('name', c_char_p),
        ('host_address', c_uint64),
        ('size', c_uint64),
        ('flags', c_uint32),
    ]


KVM_MEM_REGISTER_FIXED_REGION = IOW(KVMIO, 0xf5, KVMFixedRegion)


# Available with KVM_CAP_MEM_RW
class KVMMemRW(Structure):
    _fields_ = [
        # source and dest are always host pointers
        ('source', c_uint64),
        ('dest', c_uint64),
        ('is_write', c_uint64),
        ('length', c_uint64),
    ]


KVM_MEM_RW = IOW(KVMIO, 0xf3, KVMMemRW)

# TODO: implement remaining symbolic execution extensions
# KVM_FORCE_EXIT
# KVM_DISK_RW
# KVM_DEV_SNAPSHOT
# KVM_SET_CLOCK_SCALE
