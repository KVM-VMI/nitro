#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>

#include "libnitro.h"
#include "nitro.h"

#define KVM_NODE "/dev/kvm"

int kvm_fd;
int kvm_vmfd;
struct nitro_vcpus vcpus;

int kvm_ioctl(int type, ...)
{
    int ret;
    void *arg;
    va_list ap;

    va_start(ap, type);
    arg = va_arg(ap, void *);
    va_end(ap);

    ret = ioctl(kvm_fd, type, arg);
    if (ret == -1)
        ret = -errno;

    return ret;
}

int kvm_vm_ioctl(int type, ...)
{
    int ret;
    void *arg;
    va_list ap;

    va_start(ap, type);
    arg = va_arg(ap, void *);
    va_end(ap);

    ret = ioctl(kvm_vmfd, type, arg);
    if (ret == -1)
        ret = -errno;

    return ret;
}

int kvm_vcpu_ioctl(int vcpu_fd,int type, ...)
{
    int ret;
    void *arg;
    va_list ap;

    va_start(ap, type);
    arg = va_arg(ap, void *);
    va_end(ap);

    ret = ioctl(vcpu_fd, type, arg);
    if (ret == -1)
        ret = -errno;

    return ret;
}

int init_kvm(){
  kvm_vmfd = 0;
  memset(&vcpus,0,sizeof(struct nitro_vcpus));
  
  if((kvm_fd = open(KVM_NODE, O_RDWR)) < 0){
    kvm_fd = 0;
    return -errno;
  }
  
  return 0;
}

int close_kvm(){
  int i;
  
  for(i=0;i<vcpus.num_vcpus;i++){
    if(vcpus.fds[i]>0)
      close(vcpus.fds[i]);
  }
  
  if(kvm_vmfd>0){
    close(kvm_vmfd);
  }
  
  close(kvm_fd);
  return 0;
}




int get_num_vms(){
  return kvm_ioctl(KVM_NITRO_NUM_VMS);
}

int attach_vm(pid_t creator){
  int rv=0;
  
  kvm_vmfd = kvm_ioctl(KVM_NITRO_ATTACH_VM,&creator);
  
  if(kvm_vmfd<0)
    rv = kvm_vmfd;
  return rv;
}

int attach_vcpus(){
  int rv;
  
  rv = kvm_vm_ioctl(KVM_NITRO_ATTACH_VCPUS,&vcpus);
  
  if(rv == 0)
    rv = vcpus.num_vcpus;
  
  return rv;
}


int set_syscall_trap(bool enabled){
  return kvm_vm_ioctl(KVM_NITRO_SET_SYSCALL_TRAP,&enabled);
}

int get_regs(int vcpu_id, struct kvm_regs *regs){
  if(vcpu_id >= vcpus.num_vcpus)
    return -1;
  
  return kvm_vcpu_ioctl(vcpus.fds[vcpu_id],KVM_NITRO_GET_REGS,regs);
}

int get_sregs(int vcpu_id, struct kvm_sregs *sregs){
  if(vcpu_id >= vcpus.num_vcpus)
    return -1;
  
  return kvm_vcpu_ioctl(vcpus.fds[vcpu_id],KVM_NITRO_GET_SREGS,sregs);
}

int get_event(int vcpu_id, union event_data *ed){
  if(vcpu_id >= vcpus.num_vcpus)
    return -1;
  return kvm_vcpu_ioctl(vcpus.fds[vcpu_id],KVM_NITRO_GET_EVENT,ed);
}

int continue_vm(int vcpu_id){
  if(vcpu_id >= vcpus.num_vcpus)
    return -1;
  return kvm_vcpu_ioctl(vcpus.fds[vcpu_id],KVM_NITRO_CONTINUE);
}



