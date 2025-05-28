#  Bomb Challenge Write-up

## Introduction

The bomb challenge consists of six phases. Each phase requires providing the correct input to prevent the bomb from `“exploding.”` If the input is wrong, the `explode_bomb()` function is called, terminating the program (or triggering a simulated explosion). Let’s break down the first three phases.

## Phase 1

**Source code:**

```c
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

- The input string a1 is compared to `"Public speaking is very easy."` using the strings_not_equal function.

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

- The first number must be `1`.

- Each subsequent number is calculated as the previous number multiplied by the index (starting from 2).

Let’s compute the correct sequence step-by-step:

1. **v3[0] = `1`**

2. **v3[1] = `1 * 2 = 2`**

3. **v3[2] = `2 * 3 = 6`**

4. **v3[3] = `6 * 4 = 24`**

5. **v3[4] = `24 * 5 = 120`**

6. **v3[5] = `120 * 6 = 720`**

Correct input for phase 2:

```c
1 2 6 24 120 720
```

## phase 3

**Source code:**

```c
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

- The input format is: `<number> <char> <number>` (e.g., 0 q 777).

- The first number (v3) determines the case `(0–7)`.

- Each case defines:

    - A target integer (v5) that must match.

    - A target character (v2) that must match the middle character (v4).

- The target characters are defined as `ASCII` values in decimal:

    - `113 = q`

    - `98 = b`

    - `107 = k`

    - `111 = o`

    - `116 = t`

    - `118 = v`

Example for case 0:

  -  `v3 = 0`

  - `v2 = 113 (q)`

  - `v5 = 777`

  - `v4 = q`
    
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

```c
1 b 214
```

## Phase 4
**Source code:**

```C
int __cdecl func4(int a1)
{
  if ( a1 <= 1 )
    return 1;
  return func4(a1 - 1) + func4(a1 - 2);
}

int __cdecl phase_4(char *s)
{
  int result; // eax
  int v2; // [esp+14h] [ebp-4h] BYREF

  if ( sscanf(s, "%d", &v2) != 1 || v2 <= 0 )
    explode_bomb();
  result = func4(v2);
  if ( result != 55 )
    explode_bomb();
  return result;
}
```

**Analysis & Solution:**

- The function phase_4 reads an integer from the input string.

- It calls func4 with that integer as an argument.

- func4 is a classic `Fibonacci` sequence function:

  - For `a1 <= 1`, it returns 1.

  - Otherwise, it returns the sum of the two preceding numbers.

- phase_4 expects the output of func4 to be `55`. So we need to find an input number `n` such that the `n-th Fibonacci number equals 55`.

Let’s compute the sequence:

1. `` F(0) = 1``

2. `F(1) = 1`

3. `F(2) = 2`

4. `F(3) = 3`

5. `F(4) = 5`

6. `F(5) = 8`

7. `F(6) = 13`

8. `F(7) = 21`

9. `F(8) = 34`

10. `F(9) = 55`

The correct input is `9`.

Correct input for phase 4:

```bash
9
```

## Phase 5
**Source code:**

```c
int __cdecl phase_5(_BYTE *a1)
{
  int i; // edx
  int result; // eax
  _BYTE v3[8]; // [esp+10h] [ebp-8h] BYREF

  if ( string_length(a1) != 6 )
    explode_bomb();
  for ( i = 0; i <= 5; ++i )
    v3[i] = array_123[a1[i] & 0xF];
  v3[6] = 0;
  result = strings_not_equal(v3, "giants");
  if ( result )
    explode_bomb();
  return result;
}
```
**Supporting data:**
```bash
_BYTE array_123[16] = { 105, 115, 114, 118, 101, 97, 119, 104, 111, 98, 112, 110, 117, 116, 102, 103 }; // corresponds to: "isrveawhobpnutfg"
```
**Analysis & Solution:**

1. Input must be 6 characters long `(string_length(a1) == 6)`.

2. For each character in the input, we mask it with `0xF` (i.e., take the last `4 bits`) and use it as an index into `array_123`.

3. The result must be the string `"giants"`.

So the program does:

```c
for ( i = 0; i < 6; ++i )
  v3[i] = array_123[a1[i] & 0xF];
```

We know that:
```c
v3 = "giants"
```

So we need to find 6 input bytes such that:

```c
array_123[a1[0] & 0xF] = 'g'
array_123[a1[1] & 0xF] = 'i'
array_123[a1[2] & 0xF] = 'a'
array_123[a1[3] & 0xF] = 'n'
array_123[a1[4] & 0xF] = 't'
array_123[a1[5] & 0xF] = 's'
```

Let’s map them back:

```c
array_123 index:  0  1   2    3   4  5   6   7   8  9   10  11  12  13  14  15
array_123 value: 105 115 114 118 101 97 119 104 111 98  112 110 117 116 102 103
char:             i   s   r   v   e  a   w   h   o   b   p   n   u   t   f   g
```

Target indices for `"giants"`:

```c
'g' → index 15  (a1[0] & 0xF = 15)
'i' → index 0   (a1[1] & 0xF = 0)
'a' → index 5   (a1[2] & 0xF = 5)
'n' → index 11  (a1[3] & 0xF = 11)
't' → index 13  (a1[4] & 0xF = 13)
's' → index 1   (a1[5] & 0xF = 1)
```

We choose **printable ASCII** characters whose last `4 bits` match:

| Needed index | Example printable character |
| ------------ | --------------------------- |
| 15           | 'o' (111)                   |
| 0            | 'p' (112)                   |
| 5            | 'u' (117)                   |
| 11           | 'k' (107)                   |
| 13           | 'm' (109)                   |
| 1            | 'q' (113)                   |


**Final input to defuse phase 5:**

```c
opukmq
```

## Phase 6
**Source code:**

```c
int __cdecl phase_6(char *s)
{
  int i; // edi
  int j; // ebx
  int k; // edi
  _DWORD *v4; // esi
  int m; // ebx
  int v6; // esi
  int n; // edi
  int v8; // eax
  int v9; // esi
  int ii; // edi
  int result; // eax
  int v12; // [esp+24h] [ebp-34h]
  _DWORD v13[6]; // [esp+28h] [ebp-30h]
  int v14[6]; // [esp+40h] [ebp-18h] BYREF

  read_six_numbers(s, (int)v14);
  for ( i = 0; i <= 5; ++i )
  {
    if ( (unsigned int)(v14[i] - 1) > 5 )
      explode_bomb();
    for ( j = i + 1; j <= 5; ++j )
    {
      if ( v14[i] == v14[j] )
        explode_bomb();
    }
  }
  for ( k = 0; k <= 5; ++k )
  {
    v4 = &node1;
    for ( m = 1; m < v14[k]; ++m )
      v4 = (_DWORD *)v4[2];
    v13[k] = v4;
  }
  v6 = v13[0];
  v12 = v13[0];
  for ( n = 1; n <= 5; ++n )
  {
    v8 = v13[n];
    *(_DWORD *)(v6 + 8) = v8;
    v6 = v8;
  }
  *(_DWORD *)(v8 + 8) = 0;
  v9 = v12;
  for ( ii = 0; ii <= 4; ++ii )
  {
    result = *(_DWORD *)v9;
    if ( *(_DWORD *)v9 < **(_DWORD **)(v9 + 8) )
      explode_bomb();
    v9 = *(_DWORD *)(v9 + 8);
  }
  return result;
}
```

**Supporting data:**
This phase uses a linked list of 6 nodes (node1…node6), each containing a value and a next pointer.

**Analysis & Solution:**

1. **Input parsing**:

    - Reads 6 numbers into `v14[]`.

    - Each must be in the range `1..6` (validated by if ( `(unsigned int)(v14[i] - 1) > 5 )`).

    - Must be unique (checked by nested loop).

2. **Node mapping:**

```c
for ( k = 0; k <= 5; ++k )
{
  v4 = &node1;
  for ( m = 1; m < v14[k]; ++m )
    v4 = (_DWORD *)v4[2];
  v13[k] = v4;
}
```
This converts each input number to a pointer to the corresponding linked list node.

3. **Rebuilding the list:**

    - Links nodes in the order of input:

```c
  for ( n = 1; n <= 5; ++n )
  {
    v8 = v13[n];
    *(_DWORD *)(v6 + 8) = v8;
    v6 = v8;
  }
```
   - Ends the list with `NULL`.

4. **Final check:**

```c
for ( ii = 0; ii <= 4; ++ii )
{
  result = *(_DWORD *)v9;
  if ( *(_DWORD *)v9 < **(_DWORD **)(v9 + 8) )
    explode_bomb();
  v9 = *(_DWORD *)(v9 + 8);
}
```

   - Traverses the rebuilt list.

   - Each node’s value must be greater than or equal to the next node’s value.

   - So the final list must be sorted in descending order by value.

5. **Solution:**

    - Provide the indices of nodes in descending order of their value.

    - For example, if the original node values (in linked list order) are:

  ```yaml
  Node 1: 484
  Node 2: 219
  Node 3: 888
  Node 4: 748
  Node 5: 372
  Node 6: 111
  ```
The descending order of values: `888, 748, 484, 372, 219, 111.`
Map back to their **indices** in the original linked list: `3, 4, 1, 5, 2, 6.`

-**Final input:**

```c
3 4 1 5 2 6
```