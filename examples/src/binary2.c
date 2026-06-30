#include <stdio.h>

int main(void)
{
    int no[3];

    printf("\nSum calculator =D\n");
    printf("tip: enter first = 0 and second = 0 to exit\n");

    while (1) {
        printf("\nEnter first number: ");
        scanf("%d", &no[0]);

        printf("Enter first second: ");
        scanf("%d", &no[1]);

        no[2] = no[0] + no[1];

        if(no[0] == 0 && no[1] == 0)
            return 0;

        printf("The sum is: %d\n", no[2]);
    }

    return 0;
}
