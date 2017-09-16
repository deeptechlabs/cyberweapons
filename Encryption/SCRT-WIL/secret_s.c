/*
  Author:  Pate Williams (c) 1997

  Shamir secret sharing. See "Applied Cryptography"
  by Bruce Schneier second edition 23.2 Section
  pages 528 - 529. Also see "A Course in
  Computational Algebraic Number Theory" by Henri
  Cohen Algorithm 2.2.1 pages 48 - 49.
*/

#include <assert.h>
#include <malloc.h>
#include <stdio.h>

long **create_square_matrix(long n)
{
  long i, **matrix = calloc(n, sizeof(long *));

  assert(matrix != 0);
  for (i = 0; i < n; i++) {
    matrix[i] = calloc(n, sizeof(long));
    assert(matrix[i] != 0);
  }
  return matrix;
}

void delete_matrix(long n, long **matrix)
{
  long i;

  for (i = 0; i < n; i++) free(matrix[i]);
  free(matrix);
}

void extended_euclid(long a, long b, long *x, long *y, long *d)
{
  long q, r, x1, x2, y1, y2;

  if (b == 0) {
    *d = a, *x = 1, *y = 0;
    return;
  }
  x2 = 1, x1 = 0, y2 = 0, y1 = 1;
  while (b > 0) {
    q = a / b, r = a - q * b;
    *x = x2 - q * x1, *y = y2 - q * y1;
    a = b, b = r;
    x2 = x1, x1 = *x;
    y2 = y1, y1 = *y;
  }
  *d = a, *x = x2, *y = y2;
}

long inv(long number, long modulus)
{
  long d, x, y;

  extended_euclid(number, modulus, &x, &y, &d);
  assert(d == 1);
  if (x < 0) x += modulus;
  return x;
}

void gaussian_elimination(long n, long p, long *b, long *x, long **m)
{
  int found;
  long ck, d, i, j, k, l, sum, t;

  for (j = 0; j < n - 1; j++) {
    found = 0, i = j;
    while (!found && i < n) {
      found = m[i][j] != 0;
      if (!found) i++;
    }
    assert(found != 0);
    if (i > j) {
      /* exchange colums */
      for (l = j; l < n; l++) {
        t = m[i][l], m[i][l] = m[j][l], m[j][l] = t;
        t = b[i], b[i] = b[j], b[j] = t;
      }
    }
    d = inv(m[j][j], p);
    for (k = j + 1; k < n; k++) {
      ck = (d * m[k][j]) % p;
      if (ck < 0) ck += p;
      for (l = j + 1; l < n; l++) {
        m[k][l] -= ck * m[j][l];
        m[k][l] %= p;
        if (m[k][l] < 0) m[k][l] += p;
      }
      b[k] -= ck * b[j];
      b[k] %= p;
      if (b[k] < 0) b[k] += p;
    }
  }
  for (i = n - 1; i >= 0; i--) {
    sum = 0;
    for (j = i + 1; j < n; j++)
      sum += m[i][j] * x[j];
    x[i] = (inv(m[i][i], p) * (b[i] - sum)) % p;
    if (x[i] < 0) x[i] += p;
  }
}

long F(long a, long b, long M, long x, long p)
{
  return (a * x * x + b * x + M) % p;
}

int main(void)
{
  long b[3], i, **m = create_square_matrix(3), n = 3;
  long p = 13, x[3];

  m[0][0] =  4, m[0][1] = 2, m[0][2] = 1;
  m[1][0] =  9, m[1][1] = 3, m[1][2] = 1;
  m[2][0] = 25, m[2][1] = 5, m[2][2] = 1;
  b[0] = F(7, 8, 11, 2, p);
  b[1] = F(7, 8, 11, 3, p);
  b[2] = F(7, 8, 11, 5, p);
  printf("the right hand side is as follows:\n\n");
  for (i = 0; i < n; i++)
    printf("%ld\n", b[i]);
  gaussian_elimination(n, p, b, x, m);
  printf("\nthe solution vector is as follows:\n\n");
  for (i = 0; i < n; i++)
    printf("%ld\n", x[i]);
  delete_matrix(n, m);
  return 0;
}