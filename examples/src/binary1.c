#include <stdio.h>
#include <string.h>

int main(void)
{
    char name[256];
    printf("Enters your name: ");

    scanf("%255s", name);

    if(strcmp(name, "David") == 0)
        printf("Hello, developer!\n");
    else
        printf("Hello, %s!\n", name);
    return 0;
}
