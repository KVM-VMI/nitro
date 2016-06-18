#include <stdlib.h>
#include <stdio.h>
#include <linux/types.h>
#include <linux/kvm.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "libnitro.h"
#include "nitro.h"

int go;

void sig_handler(int signum){
  /*
  int rv;
  printf("calling unset_syscall_trap()...\n");
  rv = unset_syscall_trap();
  printf("unset_syscall_trap() returned %d\n\n",rv);
  
  close_kvm();
  
  printf("recieved sigint, exiting...\n");
  exit(0);
  */
  
  go = 0;
}
  
  

int main(int argc, char **argv){
  //int num_vms;
  int num_vcpus;
  pid_t creator;
  int vmfd;
  int rv;
  struct kvm_regs regs;
  struct kvm_sregs sregs;
  
  go = 1;
  
  signal(SIGINT, sig_handler);
  
  
  if (argc < 2){
    printf("Usage: [qemu pid]\n");
    return -1;
  }
  
  printf("Initializing KVM...\n");
  if(init_kvm()){
    printf("Unable to initialize kvm, exiting.\n");
    return -1;
  }
  printf("Initialized\n\n");
  
  creator = (pid_t)atoi(argv[1]);
  printf("calling attach_vm() with creator pid: %d...\n",creator);
  vmfd = attach_vm(creator);
  if(vmfd < 0){
    printf("Error attaching to VM, exiting\n");
    return -1;
  }
  printf("attach_vm() returned %d\n\n",vmfd);
  
  printf("calling attach_vcpus()...\n");
  num_vcpus = attach_vcpus();
  printf("attach_vcpus() returned %d\n\n",num_vcpus);
  
/*
  printf("calling get_regs()...\n");
  if(get_regs(0,&regs)){
    printf("Error getting regs, exiting\n");
    return -1;
  }
  printf("get_regs() returned rip: 0x%llX\n\n",regs.rip);
  
  printf("calling get_sregs()...\n");
  if(get_sregs(0,&sregs)){
    printf("Error getting sregs, exiting\n");
    return -1;
  }
  printf("get_sregs() returned cr0: 0x%llX\n\n",sregs.cr0);
*/

  
  printf("calling set_syscall_trap()...\n");
  rv = set_syscall_trap(true);
  printf("set_syscall_trap() returned %d\n\n",rv);
  
  while(go){
    rv = get_event(0);
    
    if(get_regs(0,&regs)){
      printf("Error getting regs, exiting\n");
      continue_vm(0);
      break;
    }
    if(get_sregs(0,&sregs)){
      printf("Error getting sregs, exiting\n");
      continue_vm(0);
      break;
    }
    if(rv == KVM_NITRO_EVENT_SYSCALL)
      // printf("Syscall trapped key: 0x%lX cr3: 0x%llX rax: 0x%llX\n",event_data.syscall,sregs.cr3,regs.rax);
      printf("Syscall trapped RAX = 0x%llx | CR3 = 0x%llx\n", regs.rax, sregs.cr3);
    else if(rv == KVM_NITRO_EVENT_SYSRET)
      //printf("Sysret trapped key: 0x%lX cr3: 0x%llX\n",event_data.syscall,sregs.cr3);
      printf("Sysret trapped\n"); 
    rv = continue_vm(0);
  }

  
  printf("calling unset_syscall_trap()...\n");
  rv = set_syscall_trap(false);
  printf("unset_syscall_trap() returned %d\n\n",rv);
  
  close_kvm();
  
  return 0;
}
