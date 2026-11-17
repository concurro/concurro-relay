# Historical TLS 1.3 work

The current source keeps the Rust worker and its active fixtures. Earlier port
stages, the Python reference worker, and the Ferret LPN experiment are in signed
Git history and the archive branches below.

| History | Signed commit | Archive ref |
| ---- | ---- | ---- |
| Python native worker on main before the Rust port | `1d34016e88208e46afe1d1208fc8f1fbe75faaf1` | `archive/tls13-python-worker` |
| Rust port and phase reports | `800a1d3ca94cb797ad4980ae54d2154968994c9d` | `archive/tls13-rust-port` |
| Native optimization assessment and dependencies | `d272af2ed328e544ad9514f0d5bb2bb1c9ead763` | `archive/tls13-optimization` |
| Ferret LPN experiment, patch, and measurements | `aa8c3d0d379e3a9c0b01f7fdea29eee562efd130` | `archive/ferret-lpn-experiment` |

The unmerged `first-slice` worktree remains separate from this cleanup.
