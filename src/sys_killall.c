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
 #include <string.h>

 int __sys_killall(struct pcb_t *caller, struct sc_regs* regs)
 {
     char proc_name[100];
     uint32_t data;
     uint32_t memrg = regs->a1;
     
     //Get name of the target proc
     int i = 0;
     data = 0;
     while(data != -1){
         libread(caller, memrg, i, &data);
         proc_name[i]= data;
         if(data == -1) proc_name[i]='\0';
         i++;
     }
     printf("The procname retrieved from memregionid %d is \"%s\"\n", memrg, proc_name);
 
     // Traverse running_list 
     struct queue_t *running_list = caller->running_list;
     if (!empty(running_list)) {
        struct queue_t temp_running_list = {.size = 0};
        while (!empty(running_list)) {
            struct pcb_t* proc = dequeue(running_list);
            char *pname = strrchr(proc->path, '/');
            pname = (pname != NULL) ? (pname + 1) : proc->path;

            if (strcmp(pname, proc_name) != 0) {
                enqueue(&temp_running_list, proc);
            }
            else {
                libfree(proc, memrg);
            }
        }
        *running_list = temp_running_list;
     }

 
#ifdef MLQ_SCHED
     // Traverse mlq_ready_queue
     for (int prio = 0; prio < MAX_PRIO; prio++) {
        struct queue_t *q = &caller->mlq_ready_queue[prio];

        if (!empty(q)){
            struct queue_t temp_q = {.size = 0};
            while (!empty(q)) {
                struct pcb_t* proc = dequeue(q);
                char *pname = strrchr(proc->path, '/');
                pname = (pname != NULL) ? (pname + 1) : proc->path;

                if (strcmp(pname, proc_name) != 0) {
                    enqueue(&temp_q, proc);
                }
                else {
                    libfree(proc, memrg);
                }
            }
            *q = temp_q;
        }
    }
#endif

    return 0;
 }
 