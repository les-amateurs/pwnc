#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline))
int thing(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j, int k) {
    printf("hi!\n");
    return a + b + c + d + e + f + g + h + i + j + k;
}

int main(int argc, char **argv) {
    char *ptr = malloc(8);
    char path[] = "HELLO THERE";
    double a = 3.1415;
    double *p = &a;
    printf("a = %f\n", *p);
    return thing((int)argv[0], 1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
}