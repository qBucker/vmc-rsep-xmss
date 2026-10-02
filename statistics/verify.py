#!/usr/bin/env python3
"""verify.py — cell-by-cell comparison of a fresh cusum_mc.py run against
the reference output. Usage: python3 verify.py my_output.txt expected_output.txt
Exit 0 iff every numeric cell matches exactly (bit-reproducible seed)."""
import sys

def cells(path):
    """Extract all numeric/<1e-4 tokens that form the result grid."""
    grid = []
    for line in open(path):
        line = line.strip()
        if line.startswith("mu="):
            grid.append(line.split(None, 1)[1].split())
    return grid

def main():
    mine, ref = cells(sys.argv[1]), cells(sys.argv[2])
    if len(mine) != len(ref):
        print(f"ROW COUNT MISMATCH: {len(mine)} vs {len(ref)}"); sys.exit(1)
    bad = 0
    for i, (a, b) in enumerate(zip(mine, ref)):
        if len(a) != len(b):
            print(f"ROW {i} WIDTH MISMATCH: {len(a)} vs {len(b)}"); bad += 1; continue
        for j, (x, y) in enumerate(zip(a, b)):
            # normalize delay cells "6.4/8.0*" -> compare numeric prefix pair
            xs, ys = x.rstrip('*'), y.rstrip('*')
            if xs != ys:
                print(f"CELL MISMATCH row {i} col {j}: {x} vs {y}"); bad += 1
    if bad == 0:
        print(f"ALL CELLS MATCH ({sum(len(r) for r in ref)} cells)")
        sys.exit(0)
    print(f"{bad} MISMATCHES"); sys.exit(1)

if __name__ == "__main__":
    main()
