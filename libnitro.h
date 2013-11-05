#ifndef KFUNCS_H_
#define KFUNCS_H_

#include <linux/types.h>
#include <linux/kvm.h>

int init_kvm();
int close_kvm();

//kvm functions
int get_num_vms();
int attach_vm(pid_t);

//vm functions
int attach_vcpus();

//vcpu functions
int get_regs(int, struct kvm_regs*);
#endif //KFUNCS_H_