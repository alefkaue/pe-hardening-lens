# PE Hardening Lens

**C++ · offline defensive analysis · original personal portfolio project**

Review declared PE hardening flags, directory ranges and section permissions without executing the supplied file.

[Português](README.pt-BR.md) · [Design and limits](docs/design.md) · [Executed example output](docs/demo-output.txt)

## Run and test

C++20 compiler and CMake 3.20+. No external C++ libraries. Binaries are under build/ on single-config generators and build/Release/ with Visual Studio. Add that directory to PATH or invoke the executable explicitly.

```console
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
python examples/make_demo.py
pe-hardening-lens examples/synthetic.pe
```

## Features

- Bounds DOS/PE/optional-header and section-table parsing for PE32/PE32+.
- Reports ASLR/NX/high-entropy/CFG declarations and write-execute sections as context-dependent observations.
- Checks file-backed relocation ranges and treats certificate-directory offsets as file offsets, not RVAs.
- JSON explicitly says signatures are not verified; tests include malformed ranges, control characters and mutation smoke checks.

## Evidence and limits

Flags are declarations, not proof of effective runtime protections. No Authenticode verification, malware classification, unpacking, code execution or exploitation. Relocation contents are not fully validated.

The committed examples/output files come from synthetic local runs. They are not customer results,
professional assessments or demonstrations against third-party systems. Input paths and archive names
can still be sensitive: keep real reports private. No account, service or network configuration is changed.

## Engineering

Parsing, decisions and output are separate from CLI argument handling. Tests cover positive cases,
ambiguous evidence and malformed data. GitHub Actions builds/tests on Windows and Linux with
read-only repository permissions and actions pinned by commit. See docs/tests.txt for the recorded local run.

Built by Alef Kaue Santos Nunes with AI assistance. This does not claim professional experience or
independent vulnerability discovery. MIT covers original code and documentation.

## Reference

- [Official format/API reference](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
