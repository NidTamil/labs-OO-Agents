# Disposable Linux preparation decision

Status: **PROPOSED; no download, import, boot or configuration has occurred.**
This is an exact local-environment choice following the already approved
[restricted UI route design](scored-subset-rpc-route-decision_2026-10-21.md).
It does not ask that design question again. The existing Linux inventory listed
only stopped `docker-desktop`, so there is no separately identified lab for the
required native checks. That observation is historical and is not production
host evidence.

## Decision requested

Approve creating **one new local WSL 2 distribution**,
`cybergym-listener-proof-20261021`, for disposable platform preparation. This
stage ends after boot/configuration inventory and termination of that exact
distribution. It does **not** run the held listener probe, any held component,
staging, a provider request, or a benchmark. Native probe configuration and its
execution remain a later concrete review step.

The new distribution can use the machine's existing WSL networking and shared
VM resources. It is a separate test filesystem, not a claimed security boundary
against Windows or other WSL distributions. Existing global WSL settings,
default distribution, Docker distribution and production host remain outside
this change. No WSL update, Windows feature change, global shutdown, global
memory/CPU configuration or controller-requested package installation is included.

First boot runs the pinned image's normal initialization and enabled systemd
services. Those may create local state, open listeners, use networking or perform
package activity; they have not yet been inspected. The read-only restriction applies to the requested
inventory commands, not to the whole boot. The controller will not invoke a
package manager, enable extra services or open a probe listener. Inspect enabled
boot/OOBE configuration before import and retain that inventory. A first-boot
provisioner requiring interactive setup or additional controller-requested
downloads/package installation stops for a revised decision; do not silently
modify more image files to bypass that condition.

## Exact artifact and location

- New workspace: `D:\GLM\cybergym-disposable-linux\listener-proof-20261021`.
  Require this leaf and the distribution name to be absent; never adopt an
  existing directory, registration or VHD. Resolve ancestors and reject reparse
  points before creation. Retain download, configuration, derived-image and
  command receipts inside this workspace.
- Import location: the new workspace's `distro` child. Original and derived
  root filesystems stay in its `images` child; inventory output in `evidence`.
- Original image: [Ubuntu 24.04.5 WSL AMD64](https://releases.ubuntu.com/24.04/ubuntu-24.04.5-wsl-amd64.wsl).
  Expected SHA-256:
  `bb415d824822c4b878125729af451a5d18fb13d1cf5cbed9a7393ad64ac6039e`.
  The [official checksum listing](https://releases.ubuntu.com/24.04/SHA256SUMS)
  was read on 21 October 2026. This is an HTTPS-published checksum pin; no image
  bytes or detached-signature verification have yet been obtained.
- Download once, at most 512 MiB and 10 minutes. Fail on a different host,
  checksum mismatch or an oversized response; do not substitute a newer image.
- Require at least 20 GiB free locally before import. The latest read-only
  local observation was 847,344,762,880 bytes free on D:. It is not fresh
  admission evidence. Expanded archive limit: 8 GiB and 250,000 members.
  These are preparation checks, not a hard quota on WSL VM memory or VHD growth.

## Configuration before first boot

Inspect the pinned archive without extracting it into the repository. Prepare
a separate derived tar that replaces only the regular-file `/etc/wsl.conf`
entry (or adds it if absent). Preserve the original entry separately, including
its metadata. Reject duplicate normalized paths, path traversal, a non-directory
`etc`, or a symlink/hardlink at the target. Preserve all other members and their
metadata; verify the derived archive and record its new SHA-256 before import.
Verification must interpret PAX metadata and link aliases affecting `etc` or
`etc/wsl.conf`; unsupported overrides/layout stop this stage without import.
No archive member is extracted into Windows to perform this rewrite.

The complete new UTF-8/LF file, root-owned mode 0644, is:

```ini
[boot]
systemd=true

[automount]
enabled=false
mountFsTab=false

[interop]
enabled=false
appendWindowsPath=false

[user]
default=root
```

The changes apply to this distribution through `wsl.conf`; global `.wslconfig`
is untouched. Automount suppression and disabled Windows process interoperability
reduce incidental host access; they do not disable networking or prevent a
privileged actor from mounting filesystems. These distinctions follow the
[Microsoft configuration reference](https://learn.microsoft.com/en-us/windows/wsl/wsl-config).

## Exact operation boundary

After approval and the preceding checks, use the fixed-name import:

```text
wsl.exe --import cybergym-listener-proof-20261021 D:\GLM\cybergym-disposable-linux\listener-proof-20261021\distro D:\GLM\cybergym-disposable-linux\listener-proof-20261021\images\prepared-rootfs.tar --version 2
```

Use the same current Windows account throughout, without elevation. Record the
new registration GUID, canonical BasePath and resolved VHD identity before any
boot, then recheck that exact join immediately before every launch and named
termination. Missing, replaced or uncertain registration denies the operation.
WSL's named commands do not atomically consume that identity check: this stage
requires exclusive management of the new distribution name by the trusted local
operator/controller. Observed concurrent registration changes stop preparation;
no resistance to a malicious same-user or administrator race is claimed.
Use only explicitly named `wsl.exe --distribution
cybergym-listener-proof-20261021 --user root --exec ...` calls for read-only
inventory: `/etc/os-release`, kernel and architecture, `/etc/wsl.conf`, PID 1,
systemd version/status, boot ID, cgroup mount/type, mount table, and availability
and versions of the image's Python and shell. Do not request package installs,
create probe users/groups/units, copy repository code or secrets, open additional
listeners, or run the probe. An unsupported kernel/init/cgroup/runtime observation ends
preparation with evidence; it does not trigger repair or a different image.

Allow at most 15 minutes for download, archive preparation, import and inventory,
then up to 2 minutes for the exact owned-distribution termination/check. This
is an operator bound enforced by the preparation controller, not proof of a
boot-aware watchdog. A timeout stops new work and records any uncertain state;
do not blindly retry import or terminate an unverified registration.

After evidence capture, terminate only the newly owned registration with
`wsl.exe --terminate cybergym-listener-proof-20261021` and confirm its stopped
state. Microsoft documents [named import and termination](https://learn.microsoft.com/en-us/windows/wsl/basic-commands).
Retain its VHD and all receipts. Unregister/delete, resizing, additional distros,
and any broader cleanup require a later retention decision.
If stopped state cannot be verified within the bound, retain the unresolved
state and report it; do not label local command exit as distribution termination.

## Result and remaining proof

Success produces a stopped, uniquely identified disposable environment and its
raw inventory. It proves no production-host property, authenticated listener,
manager custody, hard deadline, cleanup, source integration or twelve-gate PASS.
The reviewed standalone listener probe still needs exact lab account/unit/source
configuration, independently checked fixture custody, native observations and
its own bounded execution record before any platform conclusion.

Local read-only observations this turn: WSL 2.6.2.0, kernel package
6.6.87.2-1 and Windows 10.0.26300.9711. These do not establish the eventual
distribution's booted kernel, systemd version or cgroup behavior.

Independent read-only proposal review identified and corrected two P2s: preserving
registration identity across later named operations, and distinguishing read-only
inventory commands from effects of normal first boot. The final delta review
found no remaining P1/P2 within this exact preparation scope. That review is not
operator approval, a platform observation or a hard isolation/resource guarantee.
