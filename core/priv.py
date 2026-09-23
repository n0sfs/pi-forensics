"""App-side access to the pif-priv privileged helper (tools/pif_priv/pif_priv.py).

Every privileged call is being moved from `sudo <tool> ...` (broad sudoers
grants, effectively root - see CLAUDE.md's corrected Sudoers section) to
`sudo -n /usr/local/sbin/pif-priv <subcommand> ...`, where the helper
validates its own arguments as root.

Migration is staged so the station is never left unable to acquire: until
install.py has installed the helper AND its root-owned config, priv_argv()
returns the caller's legacy argv unchanged. Once both exist, the helper is
used. The legacy argv (and the old grants) are removed only after every
migrated path has been verified live on the station.

`sudo -n`: never wait for a password prompt - fail at once with an error the
job log can show, instead of hanging a worker thread on a terminal that
isn't there.
"""
import os

PIF_PRIV = "/usr/local/sbin/pif-priv"
PIF_PRIV_CONFIG = "/etc/pi-forensics/priv.conf"


def priv_available():
    return os.path.isfile(PIF_PRIV) and os.path.isfile(PIF_PRIV_CONFIG)


def priv_argv(subcommand, *args, legacy):
    """The argv to run for one privileged operation - the helper's when it
    is installed, else `legacy` (the pre-migration `sudo <tool> ...` argv)."""
    if priv_available():
        return ["sudo", "-n", PIF_PRIV, subcommand, *[str(a) for a in args]]
    return list(legacy)
