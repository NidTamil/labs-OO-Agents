"""Concrete inputs for two native synthetic runs, never readiness evidence.

The controller loads this after freezing its actual files and image identity.
Live memory and launch manifests are created later from observed service and
container identities. This module neither starts a process nor signs a pass.
Credential contents never enter the immutable configuration or its summary.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from contextlib import ExitStack
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath
from types import MappingProxyType

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .capabilities import CapabilityRegistry
from .certification import CertificationPolicy
from .deepseek import AlternateModelPolicy
from .finalize import _regular_file_fd, _rooted_directory_fd
from .model_gateway import PRIMARY_CODING_PLAN_BASE_URL, PRIMARY_MODEL, ModelPolicy
from .native_tool_runtime import _strict_json
from .network import NetworkPolicy

_SHA = re.compile(r"[a-f0-9]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_FIXTURES = ("synthetic:length-header", "synthetic:chunk-table")
_POLICIES = {
    "certification_policy": "certification-policy.json",
    "campaign_policy": "campaign-policy.json",
    "alternate_policy": "alternate-model.json",
    "network_policy": "network-policy.json",
}
_ARTIFACTS = frozenset({*_POLICIES, "native_runtime", "capability_registry", "harness_manifest"})
_MODELS = {
    "openai:text-embedding-3-large": "embedding",
    "voyage:rerank-2.5": "rerank",
    "openai:gpt-5.6-luna": "chat",
}
_NATIVE_PINS = {
    "vscode_commit": "07f806f999227108933c2e30515b26eecc1fda74",
    "vscode_server_sha256": "1f65ee7af2ede2152b4f1bedf781ea28233438173eb9831a0f3f721c5d7dd6ac",
    "claude_vsix_sha256": "4d52576e7fe83a01b908e04ea8742192d432e79e2c1ee17f10d423eaf68e21ce",
}
_NATIVE_HASHES = frozenset(
    {
        "claude_extension_sha256",
        "claude_binary_sha256",
        "launcher_vsix_sha256",
        "managed_settings_sha256",
        "managed_mcp_sha256",
    }
)
_MAX_FILE_BYTES = 512 * 1024 * 1024


class RuntimeConfigError(ValueError):
    """A bounded, credential-free diagnostic for invalid controller inputs."""


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _keys(value, expected, label):
    if type(value) is not dict or set(value) != set(expected):
        raise RuntimeConfigError(f"invalid {label} fields")


def _hash(value, label):
    if type(value) is not str or not _SHA.fullmatch(value) or value == "0" * 64:
        raise RuntimeConfigError(f"invalid {label} digest")
    return value


def _path(value, *, directory=False):
    if isinstance(value, Path):
        value = str(value)
    if (
        type(value) is not str
        or not 0 < len(value) <= 4096
        or any(ord(c) < 32 for c in value)
        or any(c in {".", ".."} for c in value.replace("\\", "/").split("/"))
    ):
        raise RuntimeConfigError("invalid absolute controller path")
    path = Path(value)
    try:
        if (
            not path.is_absolute()
            or path.resolve(strict=True) != path
            or path.is_symlink()
            or (directory and not path.is_dir())
        ):
            raise ValueError
    except (OSError, ValueError, RuntimeError):
        raise RuntimeConfigError("controller path is missing, linked or not absolute") from None
    return path


def _overlap(a, b):
    return a.is_relative_to(b) or b.is_relative_to(a)


def _observe(path, *, private=False, maximum=_MAX_FILE_BYTES, capture=False):
    """Pin POSIX ancestors and bound the read by both policy and original size."""
    path = _path(path)
    try:
        with ExitStack() as opened:
            if os.name == "posix":
                root = _rooted_directory_fd(path.parent)
                opened.callback(os.close, root)
                descriptor = _regular_file_fd(root, (path.name,), "runtime input")
            else:
                descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
            opened.callback(os.close, descriptor)
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or not 0 < before.st_size <= maximum
            ):
                raise RuntimeConfigError("runtime file is empty, linked, nonregular or oversized")
            if (
                private
                and os.name == "posix"
                and (
                    before.st_uid != os.geteuid()
                    or before.st_mode & 0o077
                    or path.parent.stat().st_mode & 0o022
                )
            ):
                raise RuntimeConfigError("controller secret file permissions are not private")
            digest = hashlib.sha256()
            content = bytearray() if capture else None
            length = 0
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                while block := stream.read(min(1024 * 1024, before.st_size - length + 1)):
                    length += len(block)
                    if length > before.st_size:
                        raise RuntimeConfigError("runtime file changed while reading")
                    digest.update(block)
                    if content is not None:
                        content.extend(block)
            after = os.fstat(descriptor)
            if length != before.st_size or any(
                getattr(before, key) != getattr(after, key)
                for key in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
            ):
                raise RuntimeConfigError("runtime file changed while reading")
            return digest.hexdigest(), length, bytes(content) if content is not None else None
    except RuntimeConfigError:
        raise
    except (OSError, ValueError, RuntimeError):
        raise RuntimeConfigError("runtime file cannot be read safely") from None


@dataclass(frozen=True, slots=True)
class VerifiedFile:
    path: Path
    sha256: str
    byte_length: int

    def verify(self):
        digest, length, _ = _observe(self.path)
        if (digest, length) != (self.sha256, self.byte_length):
            raise RuntimeConfigError("frozen runtime file digest changed")

    def read_bytes(self, maximum=16 * 1024 * 1024):
        digest, length, data = _observe(self.path, maximum=maximum, capture=True)
        if (digest, length) != (self.sha256, self.byte_length):
            raise RuntimeConfigError("frozen runtime file digest changed")
        return data


def _verified(value):
    _keys(value, {"path", "sha256"}, "artifact reference")
    expected = _hash(value["sha256"], "artifact")
    path = _path(value["path"])
    actual, length, _ = _observe(path)
    if actual != expected:
        raise RuntimeConfigError("runtime artifact digest mismatch")
    return VerifiedFile(path, actual, length)


@dataclass(frozen=True, slots=True, repr=False)
class SecretFileRef:
    """Controller-only reference; explicit reads revalidate before returning bytes."""

    path: Path
    _sha256: str
    _byte_length: int

    def __repr__(self):
        return "<SecretFileRef controller-only>"

    def read_bytes(self):
        digest, length, data = _observe(self.path, private=True, maximum=65536, capture=True)
        if (digest, length) != (self._sha256, self._byte_length):
            raise RuntimeConfigError("controller secret file changed")
        return data

    def read_text(self):
        try:
            text = self.read_bytes().decode("utf-8").strip()
            if not text or "\x00" in text:
                raise ValueError
            return text
        except (UnicodeError, ValueError):
            raise RuntimeConfigError("controller secret text is invalid or changed") from None


def _secret(value, forbidden):
    _keys(value, {"path"}, "secret reference")
    path = _path(value["path"])
    if any(path.is_relative_to(root) for root in forbidden):
        raise RuntimeConfigError("controller secret path overlaps publishable runtime data")
    digest, length, _ = _observe(path, private=True, maximum=65536)
    return SecretFileRef(path, digest, length)


@dataclass(frozen=True, slots=True)
class Credentials:
    zai: SecretFileRef
    deepseek: SecretFileRef
    gbrain_read: SecretFileRef
    gbrain_write: SecretFileRef


@dataclass(frozen=True, slots=True)
class SigningKeyRef:
    key_id: str
    private_key: SecretFileRef
    public_key_sha256: str

    def load_private_key(self):
        try:
            key = serialization.load_pem_private_key(self.private_key.read_bytes(), password=None)
            if not isinstance(key, Ed25519PrivateKey):
                raise ValueError
            raw = key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            if hashlib.sha256(raw).hexdigest() != self.public_key_sha256:
                raise ValueError
            return key
        except (ValueError, TypeError):
            raise RuntimeConfigError("controller signing key or public identity mismatch") from None


@dataclass(frozen=True, slots=True)
class NativeVersions:
    vscode: str = "1.140.0"
    vscode_commit: str = _NATIVE_PINS["vscode_commit"]
    claude_extension: str = "2.1.289"
    launcher: str = "0.1.0"


@dataclass(frozen=True, slots=True)
class RuntimeBudgets:
    max_parallel_tasks: int = 1
    task_wall_timeout_sec: int = 43200
    max_model_requests_per_task: int = 600
    max_output_tokens_per_request: int = 128000
    context_tokens: int = 1000000
    deepseek_context_tokens: int = 1048576
    deepseek_max_requests: int = 36
    glm_and_memory_auxiliary_max_requests: int = 564
    deepseek_max_counted_tokens: int = 37748736
    deepseek_max_role_seconds: int = 9000
    max_concurrent_children: int = 3
    final_submission_count: int = 1


@dataclass(frozen=True, slots=True)
class SyntheticFixture:
    task_id: str
    description: VerifiedFile
    vulnerable: VerifiedFile
    fixed: VerifiedFile


@dataclass(frozen=True, slots=True)
class CertificationRun:
    run_id: str
    fixture_ids: tuple[str, str] = _FIXTURES


@dataclass(frozen=True, slots=True)
class GBrainRuntimeConfig:
    bun: VerifiedFile
    runtime: VerifiedFile
    allowed_models: Mapping[str, str]

    def command(self, credential: SecretFileRef, *, writer=False):
        self.bun.verify()
        self.runtime.verify()
        credential.read_bytes()
        return (
            "/usr/bin/env",
            f"GBRAIN_HOME={credential.path.parent.parent}",
            str(self.bun.path),
            str(self.runtime.path),
            str(credential.path),
            *(("--writer",) if writer else ()),
        )


@dataclass(frozen=True, slots=True)
class NativeRuntimeConfig:
    epoch: str
    run_ids: tuple[str, str]
    repo_root: Path
    staging_root: Path
    evidence_root: Path
    image_id: str
    source: VerifiedFile
    artifacts: Mapping[str, VerifiedFile]
    native_identity: Mapping[str, str | int]
    credentials: Credentials
    signing: SigningKeyRef
    gbrain: GBrainRuntimeConfig
    fixtures: tuple[SyntheticFixture, SyntheticFixture]
    harness_files: tuple[VerifiedFile, ...]
    registry: CapabilityRegistry
    network_policy: NetworkPolicy
    _certification_json: bytes = field(repr=False)
    _alternate_json: bytes = field(repr=False)
    versions: NativeVersions = NativeVersions()
    budgets: RuntimeBudgets = RuntimeBudgets()

    @property
    def runs(self):
        return tuple(CertificationRun(run_id) for run_id in self.run_ids)

    @property
    def certification_policy(self):
        # Pydantic frozen models contain nested mutable dicts; return fresh values.
        return CertificationPolicy.model_validate_json(self._certification_json)

    @property
    def alternate_policy(self):
        return AlternateModelPolicy.model_validate_json(self._alternate_json)

    @property
    def model_policy(self):
        return ModelPolicy(
            PRIMARY_MODEL, self.alternate_policy, self.registry.digest, PRIMARY_CODING_PLAN_BASE_URL
        )

    def verify_unchanged(self):
        for root in (self.repo_root, self.staging_root, self.evidence_root):
            _path(root, directory=True)
        self.source.verify()
        for artifact in (
            *self.artifacts.values(),
            *self.harness_files,
            self.gbrain.bun,
            self.gbrain.runtime,
        ):
            artifact.verify()
        for fixture in self.fixtures:
            for artifact in (fixture.description, fixture.vulnerable, fixture.fixed):
                artifact.verify()
        for secret in (
            self.credentials.zai,
            self.credentials.deepseek,
            self.credentials.gbrain_read,
            self.credentials.gbrain_write,
        ):
            secret.read_bytes()
        self.signing.load_private_key()

    @property
    def freeze_sha256(self):
        """Bind the actual fixture bytes as well as explicit configuration pins."""
        return hashlib.sha256(_canonical(self._public_bindings())).hexdigest()

    def safe_summary(self):
        return {**self._public_bindings(), "configuration_sha256": self.freeze_sha256}

    def _public_bindings(self):
        return {
            "schema_version": 1,
            "scope": "synthetic_native",
            "epoch": self.epoch,
            "run_ids": list(self.run_ids),
            "fixture_ids": list(_FIXTURES),
            "configuration_file_sha256": self.source.sha256,
            "image_id": self.image_id,
            "vscode_version": self.versions.vscode,
            "vscode_commit": self.versions.vscode_commit,
            "claude_extension_version": self.versions.claude_extension,
            "launcher_version": self.versions.launcher,
            "artifact_sha256": {name: item.sha256 for name, item in self.artifacts.items()},
            "fixture_sha256": {
                item.task_id: {
                    "description": item.description.sha256,
                    "vulnerable": item.vulnerable.sha256,
                    "fixed": item.fixed.sha256,
                }
                for item in self.fixtures
            },
            "capability_registry_sha256": self.registry.digest,
            "signing_key_id": self.signing.key_id,
            "signing_public_key_sha256": self.signing.public_key_sha256,
            "budgets": asdict(self.budgets),
            "validation_scope": "local input files only; live identities require observation",
        }


def _harness_files(repo, manifest):
    value = _strict_json(manifest.read_bytes())
    _keys(value, {"schema_version", "file_hashes"}, "harness manifest")
    hashes = value["file_hashes"]
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or type(hashes) is not dict
        or not 0 < len(hashes) <= 10000
    ):
        raise RuntimeConfigError("invalid harness manifest")
    files = []
    for name, digest in sorted(hashes.items()):
        if (
            type(name) is not str
            or not name
            or "\\" in name
            or ":" in name
            or PurePosixPath(name).is_absolute()
            or str(PurePosixPath(name)) != name
            or any(
                part in {".", "..", ".git", "__pycache__", "node_modules", ".local-evidence"}
                for part in name.split("/")
            )
            or name.endswith((".sqlite", ".sqlite3", ".jsonl", ".pyc"))
        ):
            raise RuntimeConfigError("invalid or mutable harness path")
        path = repo.joinpath(*PurePosixPath(name).parts)
        if not path.is_relative_to(repo):
            raise RuntimeConfigError("harness path escapes repository")
        files.append(_verified({"path": str(path), "sha256": digest}))
    return tuple(files)


def _load_runtime_config(path):
    path = _path(path)
    digest, length, data = _observe(path, maximum=1024 * 1024, capture=True)
    source = VerifiedFile(path, digest, length)
    raw = _strict_json(data)
    _keys(
        raw,
        {
            "schema_version",
            "scope",
            "epoch",
            "run_ids",
            "repo_root",
            "staging_root",
            "evidence_root",
            "image_id",
            "artifacts",
            "credentials",
            "signing",
            "gbrain",
        },
        "runtime configuration",
    )
    if (
        type(raw["schema_version"]) is not int
        or raw["schema_version"] != 1
        or raw["scope"] != "synthetic_native"
    ):
        raise RuntimeConfigError("only synthetic native configuration is permitted")
    if (
        type(raw["epoch"]) is not str
        or not _ID.fullmatch(raw["epoch"])
        or type(raw["run_ids"]) is not list
        or len(raw["run_ids"]) != 2
        or any(type(item) is not str or not _ID.fullmatch(item) for item in raw["run_ids"])
        or len(set(raw["run_ids"])) != 2
    ):
        raise RuntimeConfigError("two distinct synthetic run identities and one epoch required")
    repo, staging, evidence = (
        _path(raw[key], directory=True) for key in ("repo_root", "staging_root", "evidence_root")
    )
    if any(_overlap(a, b) for a, b in ((repo, staging), (repo, evidence), (staging, evidence))):
        raise RuntimeConfigError("repository, staging and evidence paths must be separate")
    if os.name == "posix" and evidence.stat().st_mode & 0o022:
        raise RuntimeConfigError("controller evidence directory is writable by others")
    if type(raw["image_id"]) is not str or not raw["image_id"].startswith("sha256:"):
        raise RuntimeConfigError("immutable native image ID required")
    _hash(raw["image_id"][7:], "image")
    _keys(raw["artifacts"], _ARTIFACTS, "artifact inventory")
    artifacts = {name: _verified(value) for name, value in raw["artifacts"].items()}
    if any(
        item.path.is_relative_to(staging) for item in artifacts.values()
    ) or source.path.is_relative_to(staging):
        raise RuntimeConfigError("controller artifacts must remain outside staging")
    policies = {}
    bundled = Path(__file__).resolve().parents[2] / "leaderboard/config"
    for name, filename in _POLICIES.items():
        policies[name] = _strict_json(artifacts[name].read_bytes())
        expected = _strict_json((bundled / filename).read_bytes())
        if _canonical(policies[name]) != _canonical(expected):
            raise RuntimeConfigError("runtime policy or budget differs from approved configuration")
    certification = CertificationPolicy.model_validate(policies["certification_policy"])
    alternate = AlternateModelPolicy.model_validate(policies["alternate_policy"])
    alternate.assert_ready()
    campaign = policies["campaign_policy"]
    for name, value in asdict(RuntimeBudgets()).items():
        if type(campaign.get(name)) is not type(value) or campaign[name] != value:
            raise RuntimeConfigError("campaign budgets differ from approved limits")
    native = _strict_json(artifacts["native_runtime"].read_bytes())
    _keys(native, {"schema_version", *_NATIVE_PINS, *_NATIVE_HASHES}, "native runtime identity")
    if (
        type(native["schema_version"]) is not int
        or native["schema_version"] != 1
        or any(native[name] != value for name, value in _NATIVE_PINS.items())
    ):
        raise RuntimeConfigError("native runtime differs from pinned vendor identity")
    for name in _NATIVE_HASHES:
        _hash(native[name], "native runtime")
    registry = CapabilityRegistry.load(
        artifacts["capability_registry"].path,
        expected_sha256=artifacts["capability_registry"].sha256,
    )
    network = NetworkPolicy.load(artifacts["network_policy"].path)
    # A registry loaded here can contain pending/denied entries. Its existence
    # never authorizes execution: the driver must use CapabilityAuthorizer.
    harness = _harness_files(repo, artifacts["harness_manifest"])
    _keys(
        raw["credentials"],
        {"zai", "deepseek", "gbrain_read", "gbrain_write"},
        "credential references",
    )
    credential_refs = {
        name: _secret(value, (repo, staging, evidence))
        for name, value in raw["credentials"].items()
    }
    if len({item.path for item in credential_refs.values()}) != 4:
        raise RuntimeConfigError(
            "provider and GBrain role credentials must have separate references"
        )
    credentials = Credentials(**credential_refs)
    for secret in (credentials.zai, credentials.deepseek):
        value = secret.read_text()
        if len(value) > 16384 or any(ord(char) < 32 for char in value):
            raise RuntimeConfigError("provider secret file must contain one token")
    _keys(raw["signing"], {"key_id", "private_key_path", "public_key_sha256"}, "signing reference")
    if type(raw["signing"]["key_id"]) is not str or not _ID.fullmatch(raw["signing"]["key_id"]):
        raise RuntimeConfigError("invalid signing key identity")
    signing = SigningKeyRef(
        raw["signing"]["key_id"],
        _secret({"path": raw["signing"]["private_key_path"]}, (repo, staging, evidence)),
        _hash(raw["signing"]["public_key_sha256"], "signing public key"),
    )
    signing.load_private_key()
    if signing.private_key.path in {item.path for item in credential_refs.values()}:
        raise RuntimeConfigError("signing authority requires a separate private key")
    _keys(raw["gbrain"], {"bun", "runtime", "allowed_models"}, "GBrain runtime")
    if (
        type(raw["gbrain"]["allowed_models"]) is not dict
        or raw["gbrain"]["allowed_models"] != _MODELS
    ):
        raise RuntimeConfigError("GBrain models differ from frozen auxiliary routes")
    gbrain = GBrainRuntimeConfig(
        _verified(raw["gbrain"]["bun"]),
        _verified(raw["gbrain"]["runtime"]),
        MappingProxyType(dict(_MODELS)),
    )
    if any(item.path.is_relative_to(staging) for item in (gbrain.bun, gbrain.runtime)) or (
        os.name == "posix" and not gbrain.bun.path.stat().st_mode & 0o111
    ):
        raise RuntimeConfigError("controller GBrain command is not a protected executable")
    fixtures = []
    for task_id in _FIXTURES:
        root = (
            repo / "examples/cybergym/leaderboard/certification/fixtures" / task_id.split(":", 1)[1]
        )
        files = []
        for name in ("description.txt", "vulnerable/parser.c", "fixed/parser.c"):
            target = _path(root / name)
            sha, size, _ = _observe(target, maximum=1024 * 1024)
            files.append(VerifiedFile(target, sha, size))
        fixtures.append(SyntheticFixture(task_id, *files))
    config = NativeRuntimeConfig(
        raw["epoch"],
        tuple(raw["run_ids"]),
        repo,
        staging,
        evidence,
        raw["image_id"],
        source,
        MappingProxyType(artifacts),
        MappingProxyType(native),
        credentials,
        signing,
        gbrain,
        tuple(fixtures),
        harness,
        registry,
        network,
        _canonical(certification.model_dump(mode="json")),
        _canonical(alternate.model_dump(mode="json")),
    )
    config.verify_unchanged()
    return config


def load_runtime_config(path: Path) -> NativeRuntimeConfig:
    """Load real local inputs. Does not attest their live use or launch anything."""
    try:
        return _load_runtime_config(path)
    except RuntimeConfigError:
        raise
    except Exception:
        # Validation errors can echo arbitrary input, including misplaced keys.
        raise RuntimeConfigError("runtime configuration validation failed") from None
