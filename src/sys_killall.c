/*
 * Copyright (C) 2025 pdnguyen of HCMC University of Technology VNU-HCM
 */

/* Sierra release
 * Source Code License Grant: The authors hereby grant to Licensee
 * personal permission to use and modify the Licensed Source Code
 * for the sole purpose of studying while attending the course CO2018.
 */

 #include "common.h"
 #include "syscall.h"
 #include "stdio.h"
 #include "libmem.h"
 #include "queue.h"
 #include "string.h"
 #include "stdlib.h"
 
 int __sys_killall(struct pcb_t *caller, struct sc_regs* regs)
 {
     char proc_name[100];
     uint32_t data;
 
     //hardcode for demo only
     uint32_t memrg = regs->a1;
     
     /* TODO: Get name of the target proc */
     //proc_name = libread..
     int i = 0;
     data = 0;
     while(data != -1){
         libread(caller, memrg, i, &data);
         proc_name[i]= (char)data;
         if(data == -1) proc_name[i]='\0';
         i++;
     }
     printf("The procname retrieved from memregionid %d is \"%s\"\n", memrg, proc_name);
 
     // Traverse running_list
     struct queue_t *running_list = caller->running_list;
     for (int i = 0; i < running_list->size;) {
         if (strcmp(running_list->proc[i]->path, proc_name) == 0) {
 #ifdef MMDBG
             printf("[killall] Killing running proc \"%s\" (pid=%d)\n", running_list->proc[i]->path, running_list->proc[i]->pid);
 #endif
             // Free memory of the killed process
             free(running_list->proc[i]);
             
             // Shift left: move remaining processes to the left in the array
             for (int j = i; j < running_list->size - 1; j++) {
                 running_list->proc[j] = running_list->proc[j + 1];
             }
             running_list->size--;  // Decrease the size of the running list
             // Don't increment i, stay at current index since we shifted
         } else {
             i++;  // Move to the next process
         }
     }
 
 #ifdef MLQ_SCHED
     // Traverse mlq_ready_queue
     for (int prio = 0; prio < MAX_PRIO; prio++) {
         struct queue_t *q = &caller->mlq_ready_queue[prio];
         for (int i = 0; i < q->size;) {
             if (strcmp(q->proc[i]->path, proc_name) == 0) {
 #ifdef MMDBG
                 printf("[killall] Killing ready proc \"%s\" (pid=%d) at prio %d\n", q->proc[i]->path, q->proc[i]->pid, prio);
 #endif                
                 // Free memory of the killed process
                 free(q->proc[i]);
                 
                 // Shift left: move remaining processes to the left in the array
                 for (int j = i; j < q->size - 1; j++) {
                     q->proc[j] = q->proc[j + 1];
                 }
                 q->size--;  // Decrease the size of the queue
             } else {
                 i++;  // Move to the next process
             }
         }
     }  
 #endif
 
     return 0; 
 }
 