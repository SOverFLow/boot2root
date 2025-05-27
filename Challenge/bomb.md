#  Bomb Challenge Write-up

Introduction

The bomb challenge consists of six phases. Each phase requires providing the correct input to prevent the bomb from “exploding.” If the input is wrong, the explode_bomb() function is called, terminating the program (or triggering a simulated explosion). Let’s break down the first three phases.

## Phase 1

**Source code:**

```bash
int __cdecl phase_1(_BYTE *a1)
{
  int result;

  result = strings_not_equal(a1, "Public speaking is very easy.");
  if ( result )
    explode_bomb();
  return result;
}
```

**Analysis & Solution:**

- The input string a1 is compared to "Public speaking is very easy." using the strings_not_equal function.

 - If the strings don’t match, the bomb explodes.

**Correct input for phase 1:**

```bash
Public speaking is very easy.
```

## Phase 2
**Source code:**

```c
int __cdecl read_six_numbers(char *s, int a2)
{
  int result;

  result = sscanf(s, "%d %d %d %d %d %d", a2, a2 + 4, a2 + 8, a2 + 12, a2 + 16, a2 + 20);
  if ( result <= 5 )
    explode_bomb();
  return result;
}

int __cdecl phase_2(char *s)
{
  int i;
  int result;
  int v3[6];

  read_six_numbers(s, (int)v3);
  if ( v3[0] != 1 )
    explode_bomb();
  for ( i = 1; i <= 5; ++i )
  {
    result = v3[i - 1] * (i + 1);
    if ( v3[i] != result )
      explode_bomb();
  }
  return result;
}
```

**Analysis & Solution:**

- The function read_six_numbers expects six integers separated by spaces.

- The first number must be 1.

- Each subsequent number is calculated as the previous number multiplied by the index (starting from 2).

Let’s compute the correct sequence step-by-step:

1. v3[0] = 1

2. v3[1] = 1 * 2 = 2

3. v3[2] = 2 * 3 = 6

4. v3[3] = 6 * 4 = 24

5. v3[4] = 24 * 5 = 120

6. v3[5] = 120 * 6 = 720

Correct input for phase 2:

```
1 2 6 24 120 720
```

## phase 3

**Source code:**

```bash
int __cdecl phase_3(char *s)
{
  int result;
  char v2;
  int v3;
  char v4;
  int v5;

  if ( sscanf(s, "%d %c %d", &v3, &v4, &v5) <= 2 )
    explode_bomb();
  result = v3;
  switch ( v3 )
  {
    case 0:
      v2 = 113;
      if ( v5 != 777 )
        explode_bomb();
      return result;
    case 1:
      v2 = 98;
      if ( v5 != 214 )
        explode_bomb();
      return result;
    case 2:
      v2 = 98;
      if ( v5 != 755 )
        explode_bomb();
      return result;
    case 3:
      v2 = 107;
      if ( v5 != 251 )
        explode_bomb();
      return result;
    case 4:
      v2 = 111;
      if ( v5 != 160 )
        explode_bomb();
      return result;
    case 5:
      v2 = 116;
      if ( v5 != 458 )
        explode_bomb();
      return result;
    case 6:
      v2 = 118;
      if ( v5 != 780 )
        explode_bomb();
      return result;
    case 7:
      v2 = 98;
      if ( v5 != 524 )
        explode_bomb();
      return result;
    default:
      explode_bomb();
  }
  if ( v2 != v4 )
    explode_bomb();
  return result;
}
```
**Analysis & Solution:**

- The input format is: <number> <char> <number> (e.g., 0 q 777).

- The first number (v3) determines the case (0–7).

- Each case defines:

    - A target integer (v5) that must match.

    - A target character (v2) that must match the middle character (v4).

- The target characters are defined as ASCII values in decimal:

    - 113 = q

    - 98 = b

    - 107 = k

    - 111 = o

    - 116 = t

    - 118 = v

Example for case 0:

    - v3 = 0

    - v2 = 113 (q)

    - v5 = 777

    - v4 = q
    
**Here’s the table for all cases:**

| Case | v3 | v4 (char) | v5  |
| ---- | -- | --------- | --- |
| 0    | 0  | q         | 777 |
| 1    | 1  | b         | 214 |
| 2    | 2  | b         | 755 |
| 3    | 3  | k         | 251 |
| 4    | 4  | o         | 160 |
| 5    | 5  | t         | 458 |
| 6    | 6  | v         | 780 |
| 7    | 7  | b         | 524 |


**Correct input for phase 2:**

```
1 b 214
```

