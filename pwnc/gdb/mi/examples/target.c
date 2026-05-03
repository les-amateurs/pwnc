/*
 * Test target for pwnc.gdb.mi examples.
 * Compile: gcc -g -O0 -o target target.c
 */
#include <stdio.h>
#include <string.h>

struct Point {
    int x;
    int y;
};

enum Color { RED = 0, GREEN = 1, BLUE = 2 };

int counter = 0;
struct Point origin = {10, 20};
enum Color current_color = GREEN;
char message[32] = "hello pwnc";

int add(int a, int b) {
    return a + b;
}

void update_origin(int dx, int dy) {
    origin.x += dx;
    origin.y += dy;
}

int main(int argc, char **argv) {
    counter = 42;
    origin.x = 100;
    origin.y = 200;

    int result = add(3, 4);
    counter = result;

    for (int i = 0; i < 5; i++) {
        counter += i;
        update_origin(i, i * 2);
    }

    current_color = BLUE;
    strcpy(message, "done");
    return 0;
}
