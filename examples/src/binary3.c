#include <stdio.h>

long fib(long in)
{
    if (in == 0)
        return 0;
    if (in == 1)
        return 1;
    return fib(in - 1) + fib(in - 2);
}

int main(void)
{
    long in;
    printf("Recursive Fibonacci calculator.\nBe caution on input...\n\n");
    printf("Enters input: ");

    scanf("%ld", &in);

    if (in < 0) {
        printf("Input can only be in [0, +inf)\n");
        return 1;
    }

    printf("Result is: %ld\n", fib(in));

    return 0;
}
