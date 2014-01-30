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
  int ram_fd;
  char *ram, *ram_filename;
  struct stat ram_fs;
  //int num_vms;
  int num_vcpus;
  pid_t creator;
  int vmfd;
  int rv;
  int sc[3];
  struct kvm_regs regs;
  struct kvm_sregs sregs;
  union event_data event_data;
  
  go = 1;
  
  signal(SIGINT, sig_handler);
  
  
  if (argc < 3){
    printf("Usage: [qemu pid] [guest ram filename]\n");
    return -1;
  }
  
  ram_filename = argv[2];
  
  printf("Mapping Guest Memory...\n");
  if (stat(ram_filename, &ram_fs) == -1){
    perror("stat");
    return -1;
  }
  
  if ((ram_fd = open(ram_filename,O_RDWR)) == -1){
    perror("open");
    return -1;
  }
  
  if((ram = mmap(NULL, ram_fs.st_size, (PROT_READ | PROT_WRITE), MAP_SHARED, ram_fd, 0)) == (void*)-1){
    perror("mmap");
    close(ram_fd);
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
  sc[0] = 0x9f;
  sc[1] = 0x4a;
  sc[2] = 0xaa;
  rv = set_syscall_trap(sc,3);
  printf("set_syscall_trap() returned %d\n\n",rv);
  
  while(go){
    rv = get_event(0,&event_data);
    
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
      printf("Syscall trapped key: 0x%lX cr3: 0x%llX rax: 0x%llX\n",event_data.syscall,sregs.cr3,regs.rax);
    else if(rv == KVM_NITRO_EVENT_SYSRET)
      printf("Sysret trapped key: 0x%lX cr3: 0x%llX\n",event_data.syscall,sregs.cr3);
    rv = continue_vm(0);
  }

  
  printf("calling unset_syscall_trap()...\n");
  rv = unset_syscall_trap();
  printf("unset_syscall_trap() returned %d\n\n",rv);
  
  close_kvm();
  
  munmap(ram,ram_fs.st_size);
  close(ram_fd);
  
  return 0;
}