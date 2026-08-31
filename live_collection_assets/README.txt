PI FORENSICS SUITE - LIVE COLLECTION USB
==========================================

This drive was prepared by Pi Forensics Suite's "Build Live Collection USB"
feature. It is NOT an evidence drive and holds no case data of its own -
it is a tool for collecting VOLATILE, live artifacts (running processes,
network connections, logged-on users, and similar) from a separate,
RUNNING machine you plug it into.

Nothing on this drive ever sends anything over a network. Everything it
collects is written back onto this same drive, in the two folders below.

--------------------------------------------------------------------------
WHAT'S ON THIS DRIVE
--------------------------------------------------------------------------
uac/                  UAC (Unix-like Artifacts Collector) - for Linux,
                       macOS, *BSD, and Solaris targets. Real, open-source,
                       widely-used incident-response tool: github.com/tclahr/uac
    run_collector.sh   Run this on the live target machine.
    output/            Collection results land here after a run.

windows/              A small, hand-written PowerShell collector - for
                       Windows targets. Every line of it is plain, readable
                       PowerShell - open it in Notepad and read it before
                       running it on anything you care about.
    windows_collector.ps1
    launch_collector.cmd   Double-click this to run the collector.
    results/           Collection results land here after a run.

--------------------------------------------------------------------------
HOW TO USE THIS DRIVE
--------------------------------------------------------------------------
1. Plug this drive into the LIVE target machine you want to collect from.
   Do this only with proper authorization to access that machine.

2. Linux/macOS/*BSD target:
     Open a terminal, "cd" into this drive's "uac" folder, and run:
         ./run_collector.sh
     It will try to run with root/sudo first (collects more artifacts),
     and automatically fall back to a non-root run if that isn't
     available. Read run_collector.sh before running it if you want to
     see exactly what it does - it never modifies the target system's own
     files, only reads from it.

   Windows target:
     Open this drive's "windows" folder and double-click
     "launch_collector.cmd". If Windows shows a security warning about
     running a script from removable media, that is expected - this is a
     script you (or your organization) put on this drive, not something
     downloaded from the internet.

3. When it finishes, safely eject this drive from the target machine and
   plug it back into the Pi Forensics Suite station. Use "Import
   Collection Results" (Forensic Acquisition tab) to bring the results
   into your case, with a per-file hash manifest.

--------------------------------------------------------------------------
A NOTE ON COMPATIBILITY
--------------------------------------------------------------------------
This drive is formatted exFAT, chosen specifically because it has native
read-write support on modern Windows, macOS, and Linux. A very old target
system (pre-2010 Windows, a minimal/embedded Linux with no exFAT driver)
may not be able to write results back onto it - if the collector script
reports it can't write its output, that's why.

--------------------------------------------------------------------------
Prepared by Pi Forensics Suite - https://github.com/n0sfs/pi-forensics
