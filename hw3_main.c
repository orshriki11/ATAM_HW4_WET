//
// Created by roei_ on 26/01/2023.
//
#include "hw3_part1.h"

void run_debugger(pid_t child_pid, unsigned long addr)  //addr means address of the function
{
    //the code is taken from debugger 5 in tutorials:
    int wait_status;
    struct user_regs_struct regs;
    wait(&wait_status);
    long data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)addr, NULL);
    unsigned long data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_CONT, child_pid, NULL, NULL);
    wait(&wait_status);
    ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
    ptrace(PTRACE_POKETEXT, child_pid, (void*) addr, (void*)data);
    regs.rip -=1;
    ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
    //DO SOMETHING WE WANT:
    //**************************************************
    ptrace(PTRACE_CONT, child_pid, 0, 0);
    wait(&wait_status);
    if(WIFEXITED(wait_status))
    {
        //print error
    }
    else
    {
        //print error
    }
}

pid_t run_target(const char* function, char *const argv[])
{
    pid_t pid;
    pid = fork();
    if(pid >0)
    {
        return pid;
    }
    else if(pid == 0)
    {
        if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) <0)
        {
            perror("ptrace");
            exit(1);
        }
    }
    execl(function, argv[2], NULL); //it's not the original execl parameters from tutorial
    else
    {
        perror("fork");
        exit(1);
    }
}

int main(int argc, char *const argv[])
{
    int err = 0;
    unsigned long addr = find_symbol(argv[1], argv[2], &err);

    if (err > 0)
    {
        printf("PRF:: %s will be loaded to 0x%lx\n", argv[1], addr);
    }
    else if (err == -2)
    {
        printf("PRF:: %s is not a global symbol! :(\n", argv[1]);
        return 0;
    }
    else if (err == -1)
    {
        printf("PRF:: %s not found!\n", argv[1]);
        return 0;
    }
    else if (err == -3)
    {
        printf("PRF:: %s not an executable! :(\n", argv[2]);
        return 0;
    }

    else if (err == -4)
    {
        printf("PRF:: %s is a global symbol, but will come from a shared library\n", argv[1]);
    }

    //debugger:
    pid_t child_pid;
    child_pid = run_target(argv[1]); //input argv[1] - should be the executable file path
    run_debugger(child_pid);

    return 0;
}