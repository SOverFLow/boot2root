# Thor's Turtle Drawing Challenge

## Overview
In the home directory of user `thor`, there's a file containing drawing instructions in French. The challenge involves interpreting these instructions, converting them into a Python turtle drawing, and deriving a password from the result.

## Instructions File
The file named `turtle` contains movement commands in French:

```plaintext Avance 1 spaces
Tourne droite de 1 degrees
Avance 1 spaces
Tourne droite de 1 degrees
Avance 1 spaces
Tourne droite de 1 degrees
Avance 1 spaces
Tourne droite de 1 degrees
Avance 1 spaces
Tourne droite de 1 degrees
Avance 50 spaces

Avance 100 spaces
Recule 200 spaces
Avance 100 spaces
Tourne droite de 90 degrees
Avance 100 spaces
Tourne droite de 90 degrees
Avance 100 spaces
Recule 200 spaces
```


## Solution Approach

## 1. **Recognize the Turtle Connection**: The file name and commands suggest using Python's `turtle` library which can interpret movement commands to draw shapes.

2. **Conversion to Python Script**:
   - A C program was created to convert the French instructions into a Python turtle script
   - The converter handles these command translations:
     - "Avance X spaces" → `turtle.forward(X)`
     - "Recule X spaces" → `turtle.backward(X)`
     - "Tourne droite de X degrees" → `turtle.right(X)`
     - "Tourne gauche de X degrees" → `turtle.left(X)`

## 3. **Conversion Program**:
```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main() {
    FILE *inputFile, *outputFile;
    char line[100];

    inputFile = fopen("turtle", "r");
    if (inputFile == NULL) {
        printf("Error opening input file!\n");
        return 1;
    }

    outputFile = fopen("turtle_drawing.py", "w");
    if (outputFile == NULL) {
        printf("Error creating output file!\n");
        fclose(inputFile);
        return 1;
    }

    fprintf(outputFile, "import turtle\n\n");
    fprintf(outputFile, "t = turtle.Turtle()\n");
    fprintf(outputFile, "t.speed(1)  # Set drawing speed (1=slow, 10=fast)\n\n");

    while (fgets(line, sizeof(line), inputFile)) {
        int value;
        char command[50];

        if (sscanf(line, "Avance %d spaces", &value) == 1) {
            fprintf(outputFile, "t.forward(%d)\n", value);
        }
        else if (sscanf(line, "Recule %d spaces", &value) == 1) {
            fprintf(outputFile, "t.backward(%d)\n", value);
        }
        else if (sscanf(line, "Tourne droite de %d degrees", &value) == 1) {
            fprintf(outputFile, "t.right(%d)\n", value);
        }
        else if (sscanf(line, "Tourne gauche de %d degrees", &value) == 1) {
            fprintf(outputFile, "t.left(%d)\n", value);
        }
        else if (strcmp(line, "\n") == 0) {
            fprintf(outputFile, "\n");
        }
    }

    fprintf(outputFile, "\nturtle.done()  # Keep window open\n");

    fclose(inputFile);
    fclose(outputFile);

    printf("Python script 'turtle_drawing.py' generated successfully!\n");
    return 0;
}
```

Execution Steps:

**Compile and run the C program to generate turtle_drawing.py**

**Execute the Python script: python3 turtle_drawing.py**

**The turtle will draw the word "SLASH"**

**Create an MD5 hash of "SLASH":**
<pre>echo -n "SLASH" | md5sum </pre>

Final Password

The MD5 hash of "SLASH" is:
<pre>
646da671ca01bb5d84dbb5fb2238dc8e
</pre>