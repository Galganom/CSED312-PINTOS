#define F (1 << 14)

int roundFp2Int (int x) {
  if (x >= 0) return (x + F/2) / F;
  else return (x - F/2) / F;
}

int addF (int x, int y) {return x+y;}
int addM (int x, int n) {return n*F+x;}

int multF (int x, int y) {return y*((int64_t) x) / F;}
int multM (int x, int n) {return n*x;}

int divF (int x, int y) {return F*((int64_t) x) / y;}
int divM (int x, int n) {return x/n;}

int int2F (int n) {return F*n;}
int f2Int (int x) {return x/F;}