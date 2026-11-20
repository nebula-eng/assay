#!/usr/bin/env python3
"""End-to-end assertions against the built CLI.

Why a separate script when there is a Rust test suite?

The Rust tests exercise the library through its typed API. This script exercises
the *product*: argument parsing, exit codes, JSON shape, file I/O, and the
end-to-end behaviour that a CI gate actually depends on. Those are the things a
refactor can silently break while every unit test stays green.

Usage:
    python tests/e2e.py --binary target/release/assay --samples samples

Exit code is 0 when every assertion passes, 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

# --------------------------------------------------------------------------
# Harness
# --------------------------------------------------------------------------

class Checker:
    def __init__(self, binary: Path, samples: Path) -> None:
        self.binary = binary
        self.samples = samples
        self.passed = 0
        self.failed: list[str] = []

    def run(self, *args: str, expect_code: int | None = None) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [str(self.binary), *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
        if expect_code is not None and result.returncode != expect_code:
            raise AssertionError(
                f"`assay {' '.join(args)}` exited {result.returncode}, expected {expect_code}\n"
                f"stdout: {result.stdout[:600]}\nstderr: {result.stderr[:600]}"
            )
        return result

    def analyze(self, name: str) -> tuple[int, dict[str, Any]]:
        result = self.run("analyze", str(self.samples / name), "--format", "json")
        try:
            return result.returncode, json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise AssertionError(
                f"`analyze {name}` did not emit JSON: {error}\n"
                f"stdout: {result.stdout[:400]}\nstderr: {result.stderr[:400]}"
            ) from error

    def analyze_path(self, path: str) -> tuple[int, dict[str, Any]]:
        """Analyse an absolute path, for artefacts outside the fixture corpus."""
        result = self.run("analyze", path, "--format", "json", expect_code=None)
        try:
            return result.returncode, json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise AssertionError(
                f"`analyze {path}` did not emit JSON: {error}\n"
                f"stdout: {result.stdout[:400]}\nstderr: {result.stderr[:400]}"
            ) from error

    def check(self, label: str, fn) -> None:
        try:
            fn()
        except AssertionError as error:
            self.failed.append(f"{label}: {error}")
            print(f"  FAIL  {label}")
            print(f"        {error}")
        except Exception as error:  # noqa: BLE001 - any failure is a failure
            self.failed.append(f"{label}: unexpected {type(error).__name__}: {error}")
            print(f"  ERROR {label}")
            print(f"        {type(error).__name__}: {error}")
        else:
            self.passed += 1
            print(f"  ok    {label}")


def os_corpus() -> list[str]:
    """Signed operating-system binaries to use as a false-positive canary.

    Chosen because each one has already produced a false finding: the two kernel
    libraries for the export/provider confusion, Task Manager for enumeration,
    wbadmin for self-reference, certutil for a PKI hostname, and the Application
    Compatibility shim for an error-message template.
    """
    if sys.platform == "win32":
        root = Path(os.environ.get("SystemRoot", r"C://Windows")) / "System32"
        names = [
            "kernel32.dll",
            "advapi32.dll",
            "notepad.exe",
            "Taskmgr.exe",
            "certutil.exe",
            "wbadmin.exe",
            "AcGenral.dll",
            "rdpclip.exe",
            # Added after the 4,386-file calibration run. Each was a false
            # positive that the eight-binary canary above did not catch:
            # eight Microsoft components were critical for ransomware on the
            # word "payment", ResetEngine.dll was critical for a bcdedit debug
            # flag, two .vbs scripts were high for the WSH resource-lookup
            # idiom, and a keyboard layout DLL was medium for having no
            # imports.
            "EdgeContent.dll",
            "dbgeng.dll",
            "ResetEngine.dll",
            "diagtrack.dll",
            "Windows.Payments.dll",
            "slmgr.vbs",
            "KBDNSO.DLL",
        ]
    elif sys.platform == "darwin":
        root = Path("/usr/lib")
        names = ["libSystem.B.dylib", "libz.dylib"]
    else:
        root = Path("/usr/lib/x86_64-linux-gnu")
        names = ["libc.so.6", "libm.so.6"]
    return [str(root / name) for name in names if (root / name).exists()]


PATH_CANDIDATES = os_corpus()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


# --------------------------------------------------------------------------
# Assertions
# --------------------------------------------------------------------------

def report_shape(report: dict[str, Any]) -> None:
    for key in (
        "schema_version", "tool", "artefact", "image", "entropy",
        "strings", "string_stats", "indicators", "packer",
        "techniques", "score", "findings", "diagnostics", "timing",
    ):
        require(key in report, f"report is missing `{key}`")

    require(report["schema_version"] == "1.0", "unexpected schema_version")
    require(0 <= report["score"]["score"] <= 100, "score out of range")
    require(
        report["score"]["grade"] in {"clean", "low", "medium", "high", "critical"},
        "unexpected grade",
    )
    require(
        report["artefact"]["sha256"].__len__() == 64,
        "sha256 should be 64 hex chars",
    )
    # Factors must never exceed their own ceiling.
    for factor in report["score"]["factors"]:
        require(
            factor["points"] <= factor["max_points"],
            f"factor `{factor['key']}` exceeds its ceiling",
        )


def run_all(checker: Checker) -> None:
    print("\n[1] CLI surface")

    def version() -> None:
        out = checker.run("--version", expect_code=0).stdout
        require("assay" in out, f"--version should mention the tool, got {out!r}")

    def help_lists_commands() -> None:
        out = checker.run("--help", expect_code=0).stdout
        for command in ("analyze", "batch", "sbom", "rules", "diff", "parse"):
            require(command in out, f"--help should list `{command}`")

    def rules_list() -> None:
        out = checker.run("rules", "list", expect_code=0).stdout
        require("capability-injection" in out, "built-in rules should be listed")

    checker.check("--version exits 0", version)
    checker.check("--help lists every command", help_lists_commands)
    checker.check("rules list shows the built-in corpus", rules_list)

    print("\n[2] Report shape")

    def shape_benign() -> None:
        code, report = checker.analyze("benign.exe")
        require(code == 0, f"clean sample must exit 0, got {code}")
        report_shape(report)

    checker.check("benign.exe produces a well-formed report", shape_benign)

    print("\n[3] Detector behaviour")

    def benign_is_clean() -> None:
        _, report = checker.analyze("benign.exe")
        require(report["image"]["format"] == "pe", "benign.exe should be detected as PE")
        require(
            len(report["image"]["imports"]) >= 20,
            f"expected a populated import table, got {len(report['image']['imports'])}",
        )
        require(report["score"]["score"] < 20, f"clean sample scored {report['score']['score']}")
        require(report["packer"]["signatures"] == [], "clean sample should match no packer")

    def packed_is_detected() -> None:
        code, report = checker.analyze("packed.exe")
        require(code in (1, 2), f"packed sample should fail a high threshold, got {code}")
        require("UPX" in report["packer"]["signatures"], "UPX signature not matched")
        require(report["packer"]["likelihood"] >= 70, "UPX sample should be near-certain")
        require(report["score"]["score"] >= 55, f"packed sample scored {report['score']['score']}")

    def suspicious_has_capability() -> None:
        code, report = checker.analyze("suspicious.exe")
        require(code in (1, 2), f"suspicious sample should fail a high threshold, got {code}")
        ids = {t["id"] for t in report["techniques"]}
        require("T1055" in ids, f"process injection not inferred, got {sorted(ids)}")
        require("T1056.001" in ids, "keylogging not inferred")
        kinds = {i["kind"] for i in report["indicators"]["indicators"]}
        require("url" in kinds, "URL indicator not extracted")
        require("registry_key" in kinds, "registry key not extracted")
        require(
            any(f["rule_id"] == "capability-injection" for f in report["findings"]),
            "capability-injection rule did not fire",
        )

    def ransom_hits_critical() -> None:
        code, report = checker.analyze("ransom.exe")
        require(code == 2, f"ransomware-shaped sample should exit 2, got {code}")
        require(report["score"]["grade"] == "critical", "ransom sample should grade critical")
        rule_ids = {f["rule_id"] for f in report["findings"]}
        require("impact-ransomware-shape" in rule_ids, f"expected ransomware rule, got {rule_ids}")
        kinds = {i["kind"] for i in report["indicators"]["indicators"]}
        require("bitcoin" in kinds, "Bitcoin address not extracted")

    def elf_rpath_detected() -> None:
        code, report = checker.analyze("librpath.so")
        require(report["image"]["format"] == "elf", "ELF not detected")
        require(code in (1, 2), f"RPATH sample should fail a high threshold, got {code}")
        rule_ids = {f["rule_id"] for f in report["findings"]}
        require("elf-rpath-hijack" in rule_ids, f"expected RPATH rule, got {rule_ids}")
        meta = report["image"]["metadata"]
        require(
            any("$ORIGIN" in path or "$origin" in path for path in meta.get("rpath", [])),
            f"RPATH not parsed: {meta.get('rpath')}",
        )

    def package_detected() -> None:
        _, report = checker.analyze("bundle.zip")
        require(report["image"]["format"] == "zip", "zip not detected")
        rule_ids = {f["rule_id"] for f in report["findings"]}
        require("archive-ships-executables" in rule_ids, f"expected package rule, got {rule_ids}")

    def benign_not_flagged_for_capability() -> None:
        _, report = checker.analyze("benign.exe")
        assert not report["techniques"], (
            "a plain utility must not be assigned offensive techniques, got "
            + str([t["id"] for t in report["techniques"]])
        )
        assert not report["findings"], (
            "a plain utility must not trip a rule, got "
            + str([f["rule_id"] for f in report["findings"]])
        )

    def rules_reported() -> None:
        _, report = checker.analyze("benign.exe")
        assert report["rules_evaluated"] > 0, "the report must state how many rules ran"

    def script_detected() -> None:
        code, report = checker.analyze("stager.sh")
        require(report["image"]["format"] == "script", "script not detected")
        require(code in (1, 2), f"stager should fail a high threshold, got {code}")
        rule_ids = {f["rule_id"] for f in report["findings"]}
        require("script-obfuscation-markers" in rule_ids, f"expected script rule, got {rule_ids}")

    checker.check("benign.exe scores clean with a full import table", benign_is_clean)
    checker.check("packed.exe is identified as UPX", packed_is_detected)
    checker.check("suspicious.exe yields injection + keylogging + IOCs", suspicious_has_capability)
    checker.check("ransom.exe reaches critical", ransom_hits_critical)
    checker.check("librpath.so trips the RPATH rule", elf_rpath_detected)
    checker.check("bundle.zip trips the package rule", package_detected)
    # ---- Calibration against the host OS ---------------------------------
    #
    # The fixture corpus is deliberately hostile, so it can only prove that true
    # positives still fire. It cannot prove the absence of false positives, which
    # is this tool's actual product claim. Signed operating-system binaries can:
    # whatever the analyser says about them is either right or a bug, and there is
    # no judgement call to hide behind.
    #
    # `kernel32.dll` scored 55/high with process injection before the export rule
    # existed; `advapi32.dll` scored 75/critical for ransomware; `Taskmgr.exe` was
    # a credential dumper and a defence evader; `wbadmin.exe` deleted its own
    # recovery catalogue by naming itself. Each of those was found this way.

    def os_binaries_are_not_critical() -> None:
        corpus = PATH_CANDIDATES
        if not corpus:
            return  # no system directory on this platform; nothing to assert
        worst = []
        for name in corpus:
            _, report = checker.analyze_path(name)
            if report["score"]["grade"] in ("critical", "high"):
                worst.append((report["artefact"]["name"], report["score"]["score"],
                              [f["rule_id"] for f in report["findings"]
                               if f["severity"] in ("critical", "high")]))
        assert not worst, f"signed system binaries scored high or above: {worst}"

    checker.check(
        "signed OS binaries stay below high risk", os_binaries_are_not_critical
    )
    checker.check("stager.sh trips the obfuscation rule", script_detected)
    checker.check("benign.exe is not assigned techniques or findings", benign_not_flagged_for_capability)
    checker.check("report states the rule count", rules_reported)

    print("\n[4] Thresholds and exit codes")

    def threshold_never() -> None:
        result = checker.run(
            "analyze", str(checker.samples / "ransom.exe"), "--fail-on", "never"
        )
        require(result.returncode == 0, f"--fail-on never should exit 0, got {result.returncode}")

    def threshold_medium() -> None:
        result = checker.run(
            "analyze", str(checker.samples / "bundle.zip"), "--fail-on", "medium"
        )
        require(result.returncode == 1, f"medium sample vs medium threshold should exit 1, got {result.returncode}")

    def missing_file() -> None:
        result = checker.run("analyze", "does-not-exist.bin")
        require(result.returncode == 3, f"missing file should exit 3, got {result.returncode}")

    checker.check("--fail-on never suppresses the failure", threshold_never)
    checker.check("--fail-on medium trips on a medium sample", threshold_medium)
    checker.check("a missing file exits 3", missing_file)

    print("\n[5] Secondary commands")

    def sbom_output() -> None:
        result = checker.run("sbom", str(checker.samples / "benign.exe"))
        bom = json.loads(result.stdout)
        require(bom["bomFormat"] == "CycloneDX", "bomFormat must be CycloneDX")
        require(bom["specVersion"] == "1.5", "specVersion must be 1.5")
        require(bom["serialNumber"].startswith("urn:uuid:"), "serialNumber must be a urn:uuid")
        require(isinstance(bom["components"], list), "components must be a list")
        for component in bom["components"]:
            require(
                component["version"] == "unknown",
                "versions must not be invented",
            )

    def rules_validate() -> None:
        result = checker.run("rules", "validate", "rules/builtin.json")
        require(result.returncode == 0, "built-in rules must validate")

    def diff_runs() -> None:
        result = checker.run(
            "diff",
            str(checker.samples / "benign.exe"),
            str(checker.samples / "packed.exe"),
            "--format",
            "json",
        )
        payload = json.loads(result.stdout)
        require("score_delta" in payload, "diff must report a score delta")
        require(payload["score_delta"] > 0, "packed should score higher than benign")

    def parse_only() -> None:
        result = checker.run("parse", str(checker.samples / "benign.exe"), "--format", "json")
        image = json.loads(result.stdout)
        require(image["format"] == "pe", "parse should identify the format")
        require("score" not in image, "parse must not include a score")

    def batch_output() -> None:
        result = checker.run("batch", str(checker.samples), "--format", "json")
        payload = json.loads(result.stdout)
        require(isinstance(payload, list), "batch must emit a list")
        require(len(payload) >= 7, f"batch saw {len(payload)} files, expected >= 7")

    checker.check("sbom emits CycloneDX 1.5 without invented versions", sbom_output)
    checker.check("built-in rules validate", rules_validate)
    checker.check("diff reports a positive delta for the packed sample", diff_runs)
    checker.check("parse omits scoring", parse_only)
    checker.check("batch summarises every fixture", batch_output)

    print("\n[6] Robustness")

    def empty_file() -> None:
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as handle:
            path = handle.name
        try:
            result = checker.run("analyze", path, "--format", "json")
            require(result.returncode in (0, 3), f"empty file exited {result.returncode}")
            report = json.loads(result.stdout)
            require(report["artefact"]["size"] == 0, "empty file should report size 0")
        finally:
            Path(path).unlink(missing_ok=True)

    def garbage_file() -> None:
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as handle:
            handle.write(bytes((i * 37) % 256 for i in range(4096)))
            path = handle.name
        try:
            result = checker.run("analyze", path, "--format", "json")
            require(result.returncode in (0, 3), f"garbage exited {result.returncode}")
            json.loads(result.stdout)  # must still be valid JSON
        finally:
            Path(path).unlink(missing_ok=True)

    def truncated_pe() -> None:
        # A PE header claiming far more than the file holds: the parser must
        # report the truncation rather than panic or hang.
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as handle:
            blob = bytearray(512)
            blob[0:2] = b"MZ"
            blob[0x3C:0x40] = (0x80).to_bytes(4, "little")
            blob[0x80:0x84] = b"PE\0\0"
            blob[0x84:0x86] = (0x014C).to_bytes(2, "little")
            blob[0x86:0x88] = (0xFFFF).to_bytes(2, "little")  # 65535 sections
            handle.write(bytes(blob))
            path = handle.name
        try:
            result = checker.run("analyze", path, "--format", "json")
            require(result.returncode == 3, f"hostile header should exit 3, got {result.returncode}")
            report = json.loads(result.stdout)
            require(len(report["diagnostics"]) > 0, "truncation should be reported as a diagnostic")
        finally:
            Path(path).unlink(missing_ok=True)

    checker.check("an empty file is handled", empty_file)
    checker.check("a garbage file is handled", garbage_file)
    checker.check("a hostile section count is refused, not followed", truncated_pe)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/assay", help="path to the assay binary")
    parser.add_argument("--samples", default="samples", help="fixture directory")
    args = parser.parse_args()

    binary = Path(args.binary)
    # Windows builds carry an `.exe` suffix; accept either spelling so the same
    # command works in CI and locally.
    if not binary.exists() and Path(f"{binary}.exe").exists():
        binary = Path(f"{binary}.exe")
    samples = Path(args.samples)

    if not binary.exists():
        print(f"error: binary not found at {binary}", file=sys.stderr)
        return 1
    if not samples.is_dir():
        print(f"error: samples not found at {samples} — run scripts/make_samples.py", file=sys.stderr)
        return 1

    checker = Checker(binary, samples)
    print(f"assay e2e · binary={binary} samples={samples}")
    run_all(checker)

    total = checker.passed + len(checker.failed)
    print(f"\n{checker.passed}/{total} checks passed")
    if checker.failed:
        print("\nfailures:")
        for failure in checker.failed:
            print(f"  - {failure}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
