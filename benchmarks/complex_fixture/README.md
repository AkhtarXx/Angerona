# Complex reverse-engineering fixture

Scope: Linux x86-64 ELF produced by GCC. This fixture measures deterministic
static extraction and ABI recovery; it does not measure other architectures,
binary formats, compilers, managed runtimes, or AI-agent report quality.

This deterministic C++ fixture exercises static-analysis coverage across:

- virtual dispatch, primary/secondary vtables, and Itanium RTTI;
- single, multiple, and multi-stage virtual inheritance with exact ABI offset
  semantics;
- indirect calls through a function-pointer table;
- recursive control flow;
- switch recovery;
- structures and bounded packet parsing;
- STL containers and exception metadata;
- an intentionally retained, unreachable `strcpy` sink.

Build:

```bash
g++ -std=c++20 -O2 -g -fno-omit-frame-pointer -fno-builtin \
  -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie \
  -Wl,-z,relro,-z,now fixture.cpp -o complex_fixture
```

`oracle.json` contains engine-independent expectations. Generated binaries and
engine outputs belong under `build/` and are not source artifacts.

Run the recurring benchmark (fresh, sequential, and with no default engine
timeout):

```bash
python3 -m benchmarks.complex_fixture.run_benchmark
```

The report separates user/unknown code from runtime, import, and thunk noise.
Library boundaries are retained for call provenance and unsafe-sink detection.
For C++, the quality gates require exact user class, direct-inheritance, and
multiple-inheritance base-layout agreement between Ghidra and IDA. Primary and
secondary vtable headers are compared by table address, address point, signed
offset-to-top, and ordered callable method slots. Slot scans stop at the next
ABI header, memory boundary, or independently code-referenced data object;
indirect CALL/JUMP references are not mistaken for data-object boundaries.
For Itanium VMI RTTI, non-virtual bases expose an `object_offset`. A virtual
base instead exposes `vbase_offset_slot_offset`: the signed RTTI value locates
the virtual-base offset slot in the vtable and must not be reported as a
subobject byte offset.

Virtual-inheritance gates also validate address-point prefix metadata and the
VTT. Primary `vbase_offset` entries must be declared by VMI RTTI; secondary
prefix scans are accepted only when bounded by a preceding callable vtable
slot. A VTT must be a maximal contiguous data-pointer run covering at least
two distinct, independently validated address points. Same-RTTI entries are
reported as `complete_object`; a mixed-RTTI entry is accepted as
`construction` only when its RTTI is a transitive base of the complete class
and that base itself has virtual bases. Construction address points may carry
the Itanium destructor-pair null slots, which are retained explicitly rather
than misreported as missing methods.

Secondary vtable method slots carry normalized `this`-adjustment semantics.
Fixed adjustments are checked against `offset_to_top`; virtual adjustments are
checked against validated prefix slots using mangled-thunk or x86 instruction
evidence. If optimization removes the adjustment instruction, the report keeps
the complete valid slot set and marks the method unresolved instead of
inventing one exact slot.
