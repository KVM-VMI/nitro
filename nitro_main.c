#include <stdlib.h>
#include <stdio.h>
#include <linux/types.h>
#include <linux/kvm.h>

#include "libnitro.h"

int main(int argc, char **argv){
  //int num_vms;
  int num_vcpus;
  pid_t creator;
  int vmfd;
  
  
  if (argc < 2){
    printf("Please enter a pid\n");
    return -1;
  }
  
  printf("Initializing KVM...\n");
  if(init_kvm()){
    printf("Unable to initialize kvm, exiting.\n");
    return -1;
  }
  printf("Initialized\n\n");
  
//   printf("calling get_num_vms()...\n");
//   num_vms = get_num_vms();
//   printf("get_num_vms() returned %d\n\n",num_vms);
  
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
  
  close_kvm();
  return 0;
}