/*
 * Copyright (C) 2025 pdnguyen of HCMC University of Technology VNU-HCM
 */

/* Sierra release
 * Source Code License Grant: The authors hereby grant to Licensee
 * personal permission to use and modify the Licensed Source Code
 * for the sole purpose of studying while attending the course CO2018.
 */

// #ifdef MM_PAGING
/*
 * System Library
 * Memory Module Library libmem.c
 */

#include "string.h"
#include "mm.h"
#include "syscall.h"
#include "libmem.h"
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

static pthread_mutex_t mmvm_lock = PTHREAD_MUTEX_INITIALIZER;

/*enlist_vm_freerg_list - add new rg to freerg_list
 *@mm: memory region
 *@rg_elmt: new region
 *
 */
int enlist_vm_freerg_list(struct mm_struct *mm, struct vm_rg_struct *rg_elmt)
{
  struct vm_rg_struct *rg_node = mm->mmap->vm_freerg_list;

  if (rg_elmt->rg_start >= rg_elmt->rg_end)
    return -1;

  if (rg_node != NULL)
    rg_elmt->rg_next = rg_node;

  /* Enlist the new region */
  mm->mmap->vm_freerg_list = rg_elmt;

  return 0;
}

/*get_symrg_byid - get mem region by region ID
 *@mm: memory region
 *@rgid: region ID act as symbol index of variable
 *
 */
struct vm_rg_struct *get_symrg_byid(struct mm_struct *mm, int rgid)
{
  if (rgid < 0 || rgid > PAGING_MAX_SYMTBL_SZ)
    return NULL;

  return &mm->symrgtbl[rgid];
}

/*__alloc - allocate a region memory
 *@caller: caller
 *@vmaid: ID vm area to alloc memory region
 *@rgid: memory region ID (used to identify variable in symbole table)
 *@size: allocated size
 *@alloc_addr: address of allocated memory region
 *
 */
int __alloc(struct pcb_t *caller, int vmaid, int rgid, int size, int *alloc_addr)
{
  pthread_mutex_lock(&mmvm_lock);

  struct vm_rg_struct rgnode;

  // Find free memory region
  if (get_free_vmrg_area(caller, vmaid, size, &rgnode) == 0)
  {
    caller->mm->symrgtbl[rgid].rg_start = rgnode.rg_start;
    caller->mm->symrgtbl[rgid].rg_end = rgnode.rg_end;

    *alloc_addr = rgnode.rg_start;

    pthread_mutex_unlock(&mmvm_lock);
    return 0;
  }

  // Not having free memory region yet
  int inc_sz = PAGING_PAGE_ALIGNSZ(size);
  int inc_limit_ret;

  struct vm_area_struct *cur_vma = get_vma_by_num(caller->mm, vmaid);
  if (!cur_vma)
  {
    pthread_mutex_unlock(&mmvm_lock);
    return -1;
  }

  pthread_mutex_unlock(&mmvm_lock);
  // SYSCALL
  struct sc_regs regs = {0};
  regs.a1 = SYSMEM_INC_OP; // operation: increase
  regs.a2 = vmaid;         // which VMA to expand
  regs.a3 = inc_sz;        // how much to increase
  inc_limit_ret = syscall(caller, 17, &regs);

  if (inc_limit_ret < 0)
  {
    printf("Memory limit increase failed.\n");
    // pthread_mutex_unlock(&mmvm_lock);
    return -1; // Return failure if limit increase fails
  }

  pthread_mutex_lock(&mmvm_lock);
  /* After increasing the limit, retry allocation */
  caller->mm->symrgtbl[rgid].rg_start = rgnode.rg_start;
  caller->mm->symrgtbl[rgid].rg_end = rgnode.rg_end;

  *alloc_addr = rgnode.rg_start;
#ifdef MMDBG
  printf("===== PHYSICAL MEMORY AFTER ALLOCATION =====\n");
  printf("PID=%d - Region=%d - Address=%08lx - Size=%d byte\n", caller->pid, rgid, rgnode.rg_start, size);
  print_pgtbl(caller, 0, -1); // In bảng trang
  printf("================================================================\n");
#endif

  pthread_mutex_unlock(&mmvm_lock);
  return 0;
}

/*__free - remove a region memory
 *@caller: caller
 *@vmaid: ID vm area to alloc memory region
 *@rgid: memory region ID (used to identify variable in symbole table)
 *@size: allocated size
 *
 */
int __free(struct pcb_t *caller, int vmaid, int rgid)
{
  pthread_mutex_lock(&mmvm_lock);
  if (rgid < 0 || rgid > PAGING_MAX_SYMTBL_SZ)
  {
    return -1;
  }

  struct vm_rg_struct *rgnode = get_symrg_byid(caller->mm, rgid);
  // // Check for invalid or already empty region
  if (rgnode == NULL || (rgnode->rg_start == 0 && rgnode->rg_end == 0))
  {
    printf("Invalid or already empty region");
    return -1;
  }
  /*enlist the obsoleted memory region */
  enlist_vm_freerg_list(caller->mm, rgnode);
  // /* Invalidate the symbol table entry after freeing */
  caller->mm->symrgtbl[rgid].rg_start = 0;
  caller->mm->symrgtbl[rgid].rg_end = 0;

#ifdef MMDBG
  printf("===== PHYSICAL MEMORY AFTER DEALLOCATION =====\n");
  printf("PID=%d - Region=%d\n", caller->pid, rgid);
  print_pgtbl(caller, 0, -1); // In bảng trang
  printf("================================================================\n");
#endif
  pthread_mutex_unlock(&mmvm_lock);
  return 0;
}

/*liballoc - PAGING-based allocate a region memory
 *@proc:  Process executing the instruction
 *@size: allocated size
 *@reg_index: memory region ID (used to identify variable in symbole table)
 */
int liballoc(struct pcb_t *proc, uint32_t size, uint32_t reg_index)
{
  /* TODO Implement allocation on vm area 0 */
  int addr;

  /* By default using vmaid = 0 */
  return __alloc(proc, 0, reg_index, size, &addr);
}

/*libfree - PAGING-based free a region memory
 *@proc: Process executing the instruction
 *@size: allocated size
 *@reg_index: memory region ID (used to identify variable in symbole table)
 */

int libfree(struct pcb_t *proc, uint32_t reg_index)
{
  /* TODO Implement free region */

  /* By default using vmaid = 0 */
  return __free(proc, 0, reg_index);
}

/*pg_getpage - get the page in ram
 *@mm: memory region
 *@pagenum: PGN
 *@framenum: return FPN
 *@caller: caller
 *
 */
int pg_getpage(struct mm_struct *mm, int pgn, int *fpn, struct pcb_t *caller)
{
  uint32_t pte = mm->pgd[pgn];

  // Kiểm tra 1 page có đang ở RAM không
  if (!PAGING_PAGE_PRESENT(pte))
  {
    int vicpgn, swpfpn, vicfpn;
    int tgtfpn = PAGING_SWP(pte); // frame chứa dữ liệu của page cần gọi

    // Tìm victim page từ danh sách FIFO
    find_victim_page(mm, &vicpgn);

    /* Tìm frame trống trong bộ nhớ  */
    MEMPHY_get_freefp(caller->active_mswp, &swpfpn);
    uint32_t vicpte = mm->pgd[vicpgn];
    vicfpn = PAGING_PTE_FPN(vicpte); // lấy số frame từ pte

    // Swap frame from MEMRAM to MEMSWP
    struct sc_regs regs;
    regs.a1 = SYSMEM_SWP_OP;
    regs.a2 = vicfpn;
    regs.a3 = swpfpn;
    if (syscall(caller, 17, &regs) != 0)
    {
      regs.flags = -1;
      return -1;
    };
    regs.flags = 0;
    regs.a2 = tgtfpn;
    regs.a3 = vicfpn;

    // Swap frame from MEMSWP to MEMRAM
    regs.a1 = SYSMEM_SWP_OP;
    regs.a2 = tgtfpn;
    regs.a3 = vicfpn;
    if (syscall(caller, 17, &regs) != 0)
    {
      regs.flags = -1;
      return -1;
    };

    regs.flags = 0;

    /* Update page table */
    uint32_t swptyp = caller->active_mswp_id;
    pte_set_swap(&vicpte, swptyp, swpfpn); // Victim swapped
    mm->pgd[vicpgn] = vicpte;

    pte_set_fpn(&pte, vicfpn); // Update page
    PAGING_PTE_SET_PRESENT(pte);
    mm->pgd[pgn] = pte;
    enlist_pgn_node(&caller->mm->fifo_pgn, pgn);
  }

  *fpn = PAGING_FPN(mm->pgd[pgn]);

  return 0;
}

/*pg_getval - read value at given offset
 *@mm: memory region
 *@addr: virtual address to acess
 *@value: value
 *
 */
int pg_getval(struct mm_struct *mm, int addr, BYTE *data, struct pcb_t *caller)
{
  int pgn = PAGING_PGN(addr);
  int off = PAGING_OFFST(addr);
  int fpn;

  // Check if page loaded to RAM

  if (pg_getpage(mm, pgn, &fpn, caller) != 0)
    return -1;

  int phyaddr = (fpn << PAGING_ADDR_FPN_LOBIT) + off;

  // SYSCALL
  struct sc_regs regs;
  regs.a1 = SYSMEM_IO_READ; // Operation: read from memory
  regs.a2 = phyaddr;        // Physical address to read from
  if (syscall(caller, 17, &regs) != 0)
  {
    regs.flags = -1;
    return -1;
  }

  // Update data
  *data = (BYTE)(regs.a3); // The value read from memory will be stored in regs.a3
  regs.flags = 0;
#ifdef MMDBG
  printf("===== PHYSICAL MEMORY AFTER READING =====\n");
  printf("read region=%d offset=%d value=%d\n", 1, off, *data);
  print_pgtbl(caller, 0, -1); // In bảng trang
  printf("================================================================\n");
#endif
  return 0;
}

/*pg_setval - write value to given offset
 *@mm: memory region
 *@addr: virtual address to acess
 *@value: value
 *
 */
int pg_setval(struct mm_struct *mm, int addr, BYTE value, struct pcb_t *caller)
{
  int pgn = PAGING_PGN(addr);
  int off = PAGING_OFFST(addr);
  int fpn;

  /* Get the page to MEMRAM, swap from MEMSWAP if needed */
  if (pg_getpage(mm, pgn, &fpn, caller) != 0)
  {
    return -1; /* invalid page access */
  }

  int phyaddr = (fpn << PAGING_ADDR_FPN_LOBIT) + off;

  // SYSCALL
  struct sc_regs regs;
  regs.a1 = SYSMEM_IO_WRITE; // Operation: write to memory
  regs.a2 = phyaddr;         // Physical address to write to
  regs.a3 = value;           // Value to be written to memory
  if (syscall(caller, 17, &regs) != 0)
  {

    regs.flags = -1;
    return -1;
  }
  regs.flags = 0;
  return 0;
}

/*__read - read value in region memory
 *@caller: caller
 *@vmaid: ID vm area to alloc memory region
 *@offset: offset to acess in memory region
 *@rgid: memory region ID (used to identify variable in symbole table)
 *@size: allocated size
 *
 */
int __read(struct pcb_t *caller, int vmaid, int rgid, int offset, BYTE *data)
{
  struct vm_rg_struct *currg = get_symrg_byid(caller->mm, rgid);
  struct vm_area_struct *cur_vma = get_vma_by_num(caller->mm, vmaid);

  if (currg == NULL || cur_vma == NULL) /* Invalid memory identify */
    return -1;

  pg_getval(caller->mm, currg->rg_start + offset, data, caller);

  return 0;
}

/*libread - PAGING-based read a region memory */
int libread(
    struct pcb_t *proc, // Process executing the instruction
    uint32_t source,    // Index of source register
    uint32_t offset,    // Source address = [source] + [offset]
    uint32_t *destination)
{
  BYTE data;
  int val = __read(proc, 0, source, offset, &data);

  /* TODO update result of reading action*/
  // destination
#ifdef IODUMP
  printf("===== PHYSICAL MEMORY AFTER READING =====\n");
  printf("read region=%d offset=%d value=%d\n", source, offset, data);
  printf("================================================================\n");
#ifdef PAGETBL_DUMP
  print_pgtbl(proc, 0, -1); // print max TBL

#endif
  MEMPHY_dump(proc->mram);
#endif

  return val;
}

/*__write - write a region memory
 *@caller: caller
 *@vmaid: ID vm area to alloc memory region
 *@offset: offset to acess in memory region
 *@rgid: memory region ID (used to identify variable in symbole table)
 *@size: allocated size
 *
 */
int __write(struct pcb_t *caller, int vmaid, int rgid, int offset, BYTE value)
{
  struct vm_rg_struct *currg = get_symrg_byid(caller->mm, rgid);
  struct vm_area_struct *cur_vma = get_vma_by_num(caller->mm, vmaid);

  if (currg == NULL || cur_vma == NULL) /* Invalid memory identify */
    return -1;

  pg_setval(caller->mm, currg->rg_start + offset, value, caller);

  return 0;
}

/*libwrite - PAGING-based write a region memory */
int libwrite(
    struct pcb_t *proc,   // Process executing the instruction
    BYTE data,            // Data to be wrttien into memory
    uint32_t destination, // Index of destination register
    uint32_t offset)
{
#ifdef IODUMP
  printf("===== PHYSICAL MEMORY AFTER WRITING =====\n");
  printf("write region=%d offset=%d value=%d\n", destination, offset, data);
#ifdef PAGETBL_DUMP
  print_pgtbl(proc, 0, -1); // print max TBL
  printf("================================================================\n");
#endif
  // MEMPHY_dump(proc->mram);
#endif

  return __write(proc, 0, destination, offset, data);
}

/*free_pcb_memphy - collect all memphy of pcb
 *@caller: caller
 *@vmaid: ID vm area to alloc memory region
 *@incpgnum: number of page
 */
int free_pcb_memph(struct pcb_t *caller)
{
  int pagenum, fpn;
  uint32_t pte;

  for (pagenum = 0; pagenum < PAGING_MAX_PGN; pagenum++)
  {
    pte = caller->mm->pgd[pagenum];

    if (!PAGING_PAGE_PRESENT(pte))
    {
      fpn = PAGING_PTE_FPN(pte);
      MEMPHY_put_freefp(caller->mram, fpn);
    }
    else
    {
      fpn = PAGING_PTE_SWP(pte);
      MEMPHY_put_freefp(caller->active_mswp, fpn);
    }
  }

  return 0;
}

/*find_victim_page - find victim page
 *@caller: caller
 *@pgn: return page number
 *
 */
int find_victim_page(struct mm_struct *mm, int *retpgn)
{
  // Find the oldest page (head of FIFO list)
  struct pgn_t *pg = mm->fifo_pgn;

  /* TODO: Implement the theorical mechanism to find the victim page */
  if (pg == NULL)
  {
    return -1; // No page
  }

  int flag_found = 0;
  while (pg != NULL)
  {
    if (!PAGING_PAGE_PRESENT(mm->pgd[pg->pgn]))
      pg = pg->pg_next;
    else
    {
      flag_found = 1;
      break;
    }
  }
  if (!flag_found)
    return -1;

  *retpgn = pg->pgn;          // Return page number
  mm->fifo_pgn = pg->pg_next; // Update the fifo list (remove the current head)
  // Free the node
  free(pg);

  return 0;
}

/*get_free_vmrg_area - get a free vm region
 *@caller: caller
 *@vmaid: ID vm area to alloc memory region
 *@size: allocated size
 *
 */
int get_free_vmrg_area(struct pcb_t *caller, int vmaid, int size, struct vm_rg_struct *newrg)
{
  struct vm_area_struct *cur_vma = get_vma_by_num(caller->mm, vmaid);
  if (cur_vma == NULL)
    return -1;

  struct vm_rg_struct *prev = NULL;
  struct vm_rg_struct *curr = cur_vma->vm_freerg_list;

  while (curr != NULL)
  {
    // Kiểm tra nếu vùng hiện tại không hợp lệ
    if (curr->rg_start > curr->rg_end)
    {
      prev = curr;
      curr = curr->rg_next;
      continue; // bỏ qua vùng này
    }

    unsigned long freesize = curr->rg_end - curr->rg_start + 1;
    if (freesize >= size)
    {
      newrg->rg_start = curr->rg_start;
      newrg->rg_end = curr->rg_start + size - 1;

      if (freesize > size)
      {
        curr->rg_start += size;
      }
      else
      {
        if (prev == NULL)
        {
          cur_vma->vm_freerg_list = curr->rg_next;
        }
        else
        {
          prev->rg_next = curr->rg_next;
        }
        // free(curr);
      }
      return 0;
    }

    prev = curr;
    curr = curr->rg_next;
  }

  return -1;
}

// #endif
