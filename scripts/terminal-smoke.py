#!/usr/bin/env python3
"""Local PTY tests; empty temporary store only. No host collectors or fixtures run."""
import fcntl
import json
import os
import pty
import re
import select
import struct
import subprocess
import sys
import tempfile
import termios
import time
from pathlib import Path

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else '.build/debug/tripwire').resolve())
ansi = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')

def drain(fd, seconds=0.25):
    end = time.monotonic() + seconds
    out = bytearray()
    while time.monotonic() < end:
        if select.select([fd], [], [], max(0, min(0.05, end - time.monotonic())))[0]:
            out.extend(os.read(fd, 65536))
    return bytes(out)

def frame_lines(output):
    frame = output.decode('utf-8', 'replace').rsplit('\x1b[2J', 1)[-1]
    return ansi.sub('', frame).replace('\r', '').splitlines()

def check_overview(output, width, height, ascii_only):
    lines = frame_lines(output)
    assert lines and len(lines) <= height and max(map(len, lines)) <= width
    frame = '\n'.join(lines)
    assert ('TTTTT RRRR' if ascii_only else '████████╗██████╗') in frame
    assert '=====================================================*' in frame
    assert "' * '" in frame, 'The bottom of the fuse must remain visible'
    assert 'COVERAGE UNKNOWN' in frame and 'NEVER' in frame
    assert '[q] quit' in frame and 'tripwire> _' in frame
    if height == 24:
        assert 'OPEN FINDINGS 0' in frame and 'ES loss UNKNOWN' in frame
        assert 'No findings does not establish safety.' in frame
    if ascii_only:
        assert output.isascii()

with tempfile.TemporaryDirectory(prefix='tripwire-terminal-test-') as temp:
    db = str(Path(temp) / 'events.sqlite')
    plain = subprocess.check_output([binary, 'tui', '--once', '--ascii', '--db', db])
    assert b'\x1b' not in plain and plain.isascii()
    assert b'UNKNOWN' in plain and b'92%' not in plain
    status = json.loads(subprocess.check_output([binary, 'status', '--json', '--db', db]))
    assert status['lastSample'] == 'NEVER' and status['openFindings'] == '0'
    assert 'UNKNOWN' in status['coverage']
    print('PASS plain/piped ASCII, empty-store truthfulness and JSON status')
    cases = [(b'q', 'default startup, locale unset', [], False),
             (b'\x03', 'tui, Ctrl-C', ['tui'], False),
             (b'\x04', '--ascii, Ctrl-D', ['tui', '--ascii'], True)]
    for end_key, label, arguments, ascii_only in cases:
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 80, 0, 0))
        original = termios.tcgetattr(slave)
        env = dict(os.environ, TERM='xterm-256color', LANG='en_US.UTF-8')
        if not arguments:
            for key in ['LANG', 'LC_ALL', 'LC_CTYPE']:
                env.pop(key, None)
        child = subprocess.Popen([binary, *arguments, '--db', db], stdin=slave, stdout=slave, stderr=slave, env=env)
        try:
            output = drain(master, 1.25)
            assert b'\x1b[?1049h' in output
            check_overview(output, 80, 24, ascii_only)
            for key in b'fenpbcdxojk':
                os.write(master, bytes([key])); drain(master, 0.08)
            os.write(master, b'f'); drain(master, 0.15)
            os.write(master, b'o')
            check_overview(drain(master, 0.25), 80, 24, ascii_only)
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 55, 100, 0, 0))
            check_overview(drain(master, 1.25), 100, 55, ascii_only)
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 20, 40, 0, 0))
            lines = frame_lines(drain(master, 1.25))
            assert lines and len(lines) <= 20 and max(map(len, lines)) <= 40
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 80, 0, 0))
            check_overview(drain(master, 1.25), 80, 24, ascii_only)
            os.write(master, end_key)
            tail = drain(master, 0.3)
            child.wait(timeout=3)
            assert child.returncode == 0
            assert termios.tcgetattr(slave) == original, 'Terminal settings not restored'
            assert b'\x1b[?1049l' in tail and b'\x1b[?25h' in tail
        finally:
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=3)
            os.close(master); os.close(slave)
        print('PASS 80x24 artwork/summary, navigation, resizing and restoration:', label)
