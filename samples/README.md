# Available analysis fixtures

This directory contains `crackme.c`, `build_sbpf_fixture.py`, and `program_raw.json`. Historical binary
names referenced by some tests, including `lbuz_program.elf`, are absent from
this checkout. No origin or hash is asserted for missing files.

`crackme.c` is the source fixture added for end-to-end verification. It exposes
`add(int, int)` and intentionally uses unsafe `strcpy` in `main` so extraction
can be checked against known source. Oversized input was not executed.

Build on Linux:

```bash
gcc -O0 -g -fno-builtin -fno-stack-protector -no-pie crackme.c -o crackme
```

Generated hashes depend on compiler, paths, and environment. The tested workflow
is described in [verification](../docs/VERIFICATION.md). Build executables locally;
generated binaries and raw local evidence are not included in the review archive.

Existing captured metadata with undocumented upstream provenance is excluded
from the review archive. It is not a substitute for a real binary execution test.
The C++ benchmark has source and an oracle under `benchmarks/complex_fixture/`.

`build_sbpf_fixture.py` reproducibly builds a minimal synthetic SBPF ELF with a
return-zero program. Tests use it for ELF identity, IDL parsing, and export/fusion
contracts, replacing their dependency on an absent historical binary. It is not
evidence of a deployed Solana program's correctness. Its optional machine/text
arguments also create a minimal x86 ELF for signed-routing contract tests.

```bash
python samples/build_sbpf_fixture.py /tmp/synthetic-sbpf.elf
```
