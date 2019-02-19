#include <stdio.h>
#include <time.h>
#include <stdlib.h>

int main(int argc, const char* argv[]){
    for (int i = 0; i < 99; i++){
        srand(time(NULL));
        int r = rand() % 1000000;
        char r_s[7];
        sprintf(r_s, "%d", r);
        r_s[6] = '\0';
        printf("%s.\n", r_s);
    }
}
