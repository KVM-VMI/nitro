#ifndef KFUNCS_H_
#define KFUNCS_H_

#include <linux/types.h>
#include <linux/kvm.h>

int init_kvm();
int close_kvm();

int get_num_vms();
int attach_vm(pid_t);


int detach_vm();


#endif //KFUNCS_H_