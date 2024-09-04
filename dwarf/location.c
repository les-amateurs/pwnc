volatile int thing;

int main(int argc, char **argv) {
    thing = argc + (int)argv;
}