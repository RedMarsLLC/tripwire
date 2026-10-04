"""Build and run the unprivileged transport test; never starts eslogger."""
from pathlib import Path
import subprocess
import tempfile

source = Path(__file__).with_name("SessionHelperTests.c").resolve()
with tempfile.TemporaryDirectory(prefix="tripwire-helper-test-") as directory:
    executable = Path(directory) / "helper-test"
    subprocess.run(["/usr/bin/clang", "-Wall", "-Wextra", "-Werror", str(source), "-o", str(executable)], check=True)
    subprocess.run([str(executable)], check=True, timeout=20)
