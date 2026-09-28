import re
import sys

from obfuscators.base import Obfuscator

# Two header generations: v14+ says "protected using", v10-v13 says
# "generated using ... by memcorrupt". Both are matched here.
HEADER = re.compile(
    r"This file was (?:protected|generated) using Luraph Obfuscator v(\d+)(?:\.(\d+))?(?:\.(\d+))?"
)
HEADER_LINE = re.compile(r"\s*--[ \t]*This file was protected using Luraph Obfuscator v[\d.]+[ \t]*"
                         r"\[https?://lura\.ph/?\]")

class LuraphV15(Obfuscator):
    name = "luraph_v15"
    label = "Luraph v15"
    doc = "LURAPH.md"

    def detect(self, source):
        """Any Luraph generation is recognised; `version` says which one, and
        the driver picks full devirtualization (v15) or the behaviour trace
        (older builds, whose VM layout the lifter does not model)."""
        m = HEADER.search(source[:500])
        if m:
            self.version = ".".join(g for g in m.groups() if g)
            self.major = m.group(1)
            return 1.0 if m.group(1) == "15" else 0.97

        head = source.lstrip()[:2000]
        if head.startswith("return setmetatable({") and (
                re.search(r"\[\d+\]=(bit32|buffer|string|table|math)\.\w+", head) or "LPH" in source[:200000]):
            self.version, self.major = None, "15"
            return 0.8
        self.version = self.major = None
        return 0.0

    version = None
    major = None

    def add_arguments(self, ap):
        g = ap.add_argument_group("Luraph v15")
        g.add_argument("--no-hooks", action="store_true",
                       help="do not instrument VM functions (no anti-tamper trap attribution, no lifting)")
        g.add_argument("--max-runs", type=int, default=12, help="maximum number of trace runs (trap reruns)")
        g.add_argument("--devirt-rounds", type=int, default=200,
                       help="max lift + constant-request rounds (default 200; stops early when no new "
                            "constants turn up)")

    def deobfuscate(self, job):
        from obfuscators.luraph_v15 import driver
        fixed = restore_header_newline(job.source)
        if fixed != job.source:

            print("[*] header comment ran into the code (lost newline): split it", file=sys.stderr)
            job.source = fixed
            job.source_path = job.write(job.path(".src.lua"), fixed, encoding="latin-1")
        return driver.run(job)

def restore_header_newline(source):
    """Pasted copies (e.g. Discord's message.txt) can lose the newline after
    the `-- This file was protected ... [https://lura.ph/]` line, which turns
    the whole script into that comment. Put it back."""
    m = HEADER_LINE.match(source)
    if m and source[m.end():m.end() + 1] not in ("", "\n", "\r"):
        return source[:m.end()] + "\n" + source[m.end():].lstrip(" \t")
    return source
