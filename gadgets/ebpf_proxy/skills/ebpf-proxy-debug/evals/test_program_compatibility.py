import unittest
from pathlib import Path


GADGET_ROOT = Path(__file__).resolve().parents[3]


class ProgramCompatibilityTests(unittest.TestCase):
    def test_async_io_uses_portable_raw_syscall_program(self) -> None:
        bpf = (GADGET_ROOT / "program.bpf.c").read_text()
        control = (GADGET_ROOT / "go" / "program.go").read_text()

        self.assertNotIn('SEC("ksyscall/', bpf)
        self.assertIn('SEC("raw_tracepoint/sys_enter")\nint ebpf_proxy_fs_async_enter', bpf)
        self.assertIn('"ebpf_proxy_fs_async_enter"', control)
        self.assertIn('api.GetSyscallID("io_uring_enter")', control)
        self.assertIn('api.GetSyscallID("io_submit")', control)


if __name__ == "__main__":
    unittest.main()
