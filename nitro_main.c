#include <stdlib.h>
#include <stdio.h>

#include "kfuncs.h"

int main(int argc, char **argv){
  int num_vms;
  
  printf("Starting nitro-ng...\n");
  init_kvm();
  
  num_vms = get_num_vms();
  
  close_kvm();
  return 0;
}