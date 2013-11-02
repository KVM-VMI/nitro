#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <errno.h>

#include "nitro.h"

#define KVM_NODE "/dev/kvm"


int kvm_fd;
int kvm_vmfd;

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

int init_kvm(){
  if((kvm_fd = open(KVM_NODE, O_RDWR)) < 0){
    return -errno;
  }
  
  return 0;
}

int close_kvm(){
  close(kvm_fd);
  return 0;
}




int get_num_vms(){
  int num_vms;
  
  num_vms = kvm_ioctl(KVM_NITRO_NUM_VMS);
  
  return num_vms; 
}