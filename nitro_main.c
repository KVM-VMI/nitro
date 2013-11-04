#include <stdlib.h>
#include <stdio.h>
#include <linux/types.h>
#include <linux/kvm.h>

#include "kfuncs.h"

int main(int argc, char **argv){
  int num_vms;
  pid_t creator;
  int vmfd;
  char c;
  
  
  if (argc < 2){
    printf("Please enter a pid\n");
    return -1;
  }
  
  printf("Starting nitro-ng...\n");
  init_kvm();
  
  num_vms = get_num_vms();
  printf("get_num_vms() returned %d\n",num_vms);
  
  creator = (pid_t)atoi(argv[1]);
  printf("calling init_vm() with creator pid: %d\n",creator);
  vmfd = attach_vm(creator);
  printf("init_vm() returned %d\n",vmfd);
  
  c = (char)getc(stdin);
  
  deattach_vm();
  
  close_kvm();
  return 0;
}