# copyfail-hotfix

Emergency mitigation for **CVE-2026-31431**, also known as **Copy Fail**.

This script does **not** patch the Linux kernel.

It provides a small defensive hotfix script that blocks the vulnerable
`algif_aead` kernel module from loading, attempts to unload it if it is already
loaded, rebuilds initramfs when supported, and runs a safe AF_ALG AEAD
availability check.

The real fix is to install and boot an official vendor kernel that contains the
upstream Linux kernel fix.

## What this script does

`copyfail-hotfix.sh` applies a temporary mitigation by creating a modprobe rule:

```text
install algif_aead /bin/false
blacklist algif_aead
```

The script also:

- Checks whether `algif_aead` is currently loaded
- Attempts to unload the module safely
- Rebuilds initramfs with `update-initramfs` or `dracut` when available
- Runs a safe AF_ALG AEAD check that does not exploit the system
- Provides a status command
- Provides an undo command

## Usage

```bash
chmod +x copyfail-hotfix.sh
sudo ./copyfail-hotfix.sh apply
sudo ./copyfail-hotfix.sh status
sudo ./copyfail-hotfix.sh check
```

If the module is still loaded after applying the mitigation, reboot:

```bash
sudo reboot
```

Then check again:

```bash
sudo ./copyfail-hotfix.sh status
sudo ./copyfail-hotfix.sh check
```

## Expected protected state

A protected system should show results similar to:

```text
Mitigation file: present
Runtime module state: not loaded

modprobe dry-run:
install /bin/false

Safe AF_ALG check:
OK: AF_ALG AEAD algorithm is unavailable. Mitigation appears active.
```

## Undo

To remove the mitigation file created by this script:

```bash
sudo ./copyfail-hotfix.sh undo
sudo reboot
```

After undo, the AF_ALG AEAD interface may become available again unless the
system has already been updated to a fixed kernel.

## Important notes

This is an **emergency mitigation**, not a permanent kernel fix.

Always install the official kernel update from your Linux distribution as soon
as it is available.

This mitigation may affect software that explicitly depends on the Linux
AF_ALG AEAD userspace crypto interface. Most regular desktop and server systems
are not expected to rely on this interface directly, but specialized crypto
offload setups should be tested.

On kernels where `algif_aead` is built directly into the kernel instead of being
available as a loadable module, modprobe-based blocking may not be sufficient.
Follow your distribution or vendor guidance in that case.

For untrusted workload environments such as containers, sandboxes, and CI
runners, also consider blocking AF_ALG socket creation with seccomp according
to your platform and distribution guidance.

## Tested behavior

On a tested Ubuntu/Mint-style system, before applying the mitigation, the safe
checker reported that AF_ALG AEAD bind was available.

After applying the hotfix and rebooting:

- The mitigation file remained present
- `algif_aead` was not loaded
- `modprobe -n -v algif_aead` returned `install /bin/false`
- The safe AF_ALG checker reported that AEAD was unavailable
- The public PoC failed at the AEAD bind stage with `FileNotFoundError`

This indicates that the emergency mitigation was active on the tested system.

## Disclaimer

Use this script at your own risk.

This script is provided for defensive mitigation purposes only. It is intended
to help system owners reduce exposure until an official fixed kernel is
installed and booted.
