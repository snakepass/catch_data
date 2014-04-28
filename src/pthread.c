#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>

void func(void *args)
{
    sleep(2);
    printf("this is func\n");
}

int main(int argc,char *argv[])
{
    pthread_t pid;

    if(pthread_create(&pid, NULL, func, NULL))
    {
        printf("create func failed!");
        return -1;
    }

    pthread_join(pid,NULL);
    printf("func end, main end.\n");

    return 0;
}

