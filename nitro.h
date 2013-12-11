#ifndef NITRO_H_
#define NITRO_H_

#include <linux/ioctl.h>
#include <linux/kvm.h>
#include <linux/types.h>

#define NITRO_MAX_VCPUS 64

struct nitro_vcpus{
  int num_vcpus;
  int ids[NITRO_MAX_VCPUS];
  int fds[NITRO_MAX_VCPUS];
};

struct nitro_syscall_trap{
  int *syscalls;
  int size;
};

//return reasons
#define KVM_NITRO_ERROR			0
#define KVM_NITRO_TIMEOUT		1
#define KVM_NITRO_SYSCALL_TRAPPED	2

//KVM functions
#define KVM_NITRO_NUM_VMS  	_IO(KVMIO, 0xE0)
#define KVM_NITRO_ATTACH_VM  	_IOW(KVMIO, 0xE1, pid_t)

//VM functions
#define KVM_NITRO_ATTACH_VCPUS	_IOR(KVMIO, 0xE2, struct nitro_vcpus)
#define KVM_NITRO_SET_SYSCALL_TRAP _IOW(KVMIO, 0xE3, struct nitro_syscall_trap)
#define KVM_NITRO_UNSET_SYSCALL_TRAP _IO(KVMIO, 0xE4)

//VCPU functions
#define KVM_NITRO_GET_EVENT	_IO(KVMIO, 0xE5)
#define KVM_NITRO_CONTINUE	_IO(KVMIO, 0xE6)

#endif //NITRO_H_