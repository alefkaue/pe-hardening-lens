# Design and trust boundaries

Review declared PE hardening flags, directory ranges and section permissions without executing the supplied file.

- Bounds DOS/PE/optional-header and section-table parsing for PE32/PE32+.
- Reports ASLR/NX/high-entropy/CFG declarations and write-execute sections as context-dependent observations.
- Checks file-backed relocation ranges and treats certificate-directory offsets as file offsets, not RVAs.
- JSON explicitly says signatures are not verified; tests include malformed ranges, control characters and mutation smoke checks.

Flags are declarations, not proof of effective runtime protections. No Authenticode verification, malware classification, unpacking, code execution or exploitation. Relocation contents are not fully validated.

The source snapshot is evidence supplied by the operator, not remote attestation. A metadata flag or heuristic is not proof of an attack. Tests use fixtures constructed by this repository and do not contact external targets. Do not execute or extract untrusted samples as a way to use this tool.
