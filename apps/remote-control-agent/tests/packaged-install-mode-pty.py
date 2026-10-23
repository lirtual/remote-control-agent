#!/usr/bin/env python3
"""Exercise a packaged Agent's actual Node TTY without any cloud pairing."""
import fcntl
import json
import os
import pty
import select
import subprocess
import sys
import termios
import time
from pathlib import Path

root = Path(sys.argv[1]).resolve()
node = root / 'bin/node'
module = (root / 'apps/remote-control-agent/src/install-mode.js').as_uri()
assert node.is_file() and module.startswith('file://')
code = (f'import {{ promptInstallMode }} from {json.dumps(module)};'
        'try { console.log("RESULT=" + await promptInstallMode()); }'
        'catch { console.log("CANCELLED"); process.exitCode=5; }')
cases = {
    'enter-permanent': (b'\r', 'RESULT=permanent', 0),
    'arrow-temporary': (b'\x1b[B\r', 'RESULT=temporary', 0),
    'number-temporary': (b'2', 'RESULT=temporary', 0),
    'escape-cancel': (b'\x1b', 'CANCELLED', 5),
}
for name, (keys, expected, status) in cases.items():
    master, slave = pty.openpty()
    initial = termios.tcgetattr(slave)

    def attach_terminal():
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)

    proc = subprocess.Popen([str(node), '--input-type=module', '-e', code],
                            cwd=root, stdin=slave, stdout=slave, stderr=slave,
                            preexec_fn=attach_terminal,
                            env={**os.environ, 'TERM': 'xterm-256color'})
    output = b''
    deadline = time.monotonic() + 5
    try:
        while b'2. ' not in output and time.monotonic() < deadline:
            if select.select([master], [], [], 0.1)[0]:
                try:
                    output += os.read(master, 4096)
                except OSError:
                    break
        assert b'2. ' in output, f'{name}: menu not rendered: {output[-300:]!r}'
        time.sleep(0.08)  # UI visible; allow the keypress listener to attach.
        os.write(master, keys)
        while proc.poll() is None and time.monotonic() < deadline:
            if select.select([master], [], [], 0.1)[0]:
                try:
                    output += os.read(master, 4096)
                except OSError:
                    break
        if proc.poll() is None:
            raise AssertionError(f'{name}: packaged Node TTY did not exit after selection')
        while select.select([master], [], [], 0)[0]:
            try:
                output += os.read(master, 4096)
            except OSError:
                break
        assert proc.returncode == status and expected.encode() in output, (
            name, proc.returncode, output[-450:])
        assert termios.tcgetattr(slave) == initial, f'{name}: raw TTY left enabled'
        print('PACKAGED_TTY_PASS:', name)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        os.close(master)
        os.close(slave)
print('PACKAGED_TTY_TOTAL:', len(cases))
