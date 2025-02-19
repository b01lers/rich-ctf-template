#include <stdio.h>

void setup() {{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}}

// Sample challenge which just prints the flag free to delete this
int main() {{
    setup();

    char flag_buf[128] = {{ 0 }};

    FILE *file = fopen("./flag.txt", "r");
    if (file != NULL) {{
        fread(flag_buf, sizeof(char), sizeof(flag_buf), file);
    }}

    printf("Hello I am challenge: {name} and my flag is %s\n", flag_buf);
}}
