#include <stdio.h>
#include <stdlib.h>

int *ptrs[10];

int main() {
  setbuf(stdout, NULL);
  setbuf(stdin, NULL);

  while (1) {
    printf("choice: ");
    int choice;
    scanf("%d", &choice);

    switch (choice) {
    case 0: {
      int idx;
      printf("idx: ");
      scanf("%d", &idx);

      ptrs[idx] = malloc(10);
    }
    case 1: {
      int idx;
      printf("idx: ");
      scanf("%d", &idx);
      free(ptrs[idx]);
    }
    default: {
      exit(0);
    }
    }
  }
}