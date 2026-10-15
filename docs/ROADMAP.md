# Reverse-engineering coverage roadmap

The release hardening work makes current boundaries machine-visible. The
following are engineering frontiers, not current production claims:

- Replace synthetic single-function managed-bytecode graphs with real container,
  method, exception-region, and metadata parsing for WASM, JVM, DEX, CIL, BEAM,
  Lua, Python bytecode, and V8 Ignition.
- Expand the benchmark matrix beyond Linux x86-64 ELF to PE, Mach-O, firmware,
  mobile packages, managed runtimes, and additional CPU architectures.
- Add reproducible AI-agent report-quality evaluation with binary-backed oracles,
  cost/latency accounting, and hallucination/error-rate metrics.
- Validate privacy mode against a documented local gateway deployment and add
  operating-system-level network-isolation integration tests.
