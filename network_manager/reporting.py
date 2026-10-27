"""Terminal output helpers and result collection for network checks."""

import sys
from dataclasses import dataclass, field, asdict

USE_COLOR = sys.stdout.isatty()


def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


def green(t):
    return _c("32", t)


def red(t):
    return _c("31", t)


def yellow(t):
    return _c("33", t)


def cyan(t):
    return _c("36", t)


def bold(t):
    return _c("1", t)


def dim(t):
    return _c("2", t)


STATUS_ICONS = {
    "ok": green("✔"),
    "fail": red("✘"),
    "warn": yellow("⚠"),
    "info": cyan("ℹ"),
}


@dataclass
class CheckResult:
    name: str
    status: str  # "ok" | "fail" | "warn" | "info"
    detail: str = ""
    advice: str = ""
    section: str = ""


@dataclass
class Report:
    """Collects results across all checks and renders the final summary.

    With quiet=True nothing is printed live — used by the JSON output and
    the GUI, which read `results` themselves.
    """

    results: list = field(default_factory=list)
    quiet: bool = False
    current_section: str = ""

    def add(self, name, status, detail="", advice=""):
        result = CheckResult(name, status, detail, advice, self.current_section)
        self.results.append(result)
        if not self.quiet:
            print_result(result)
        return result

    def section(self, title):
        self.current_section = title
        if self.quiet:
            return
        print()
        print(bold(cyan(f"── {title} ")) + cyan("─" * max(0, 50 - len(title))))

    def problems(self):
        return [r for r in self.results if r.status in ("fail", "warn")]

    def summary(self, verdict=None):
        print()
        print(bold(cyan("── Summary ")) + cyan("─" * 39))
        if verdict:
            status, headline, action = verdict
            print(f"  {STATUS_ICONS.get(status, ' ')} {bold(headline)}")
            if action:
                print(f"    {yellow('→')} {action}")
        problems = self.problems()
        if not problems:
            if not verdict:
                print(f"  {green('✔')} {bold('Network looks healthy.')} No issues detected.")
            return
        if verdict:
            print()
        fails = [r for r in problems if r.status == "fail"]
        warns = [r for r in problems if r.status == "warn"]
        print(f"  {bold(f'{len(fails)} problem(s), {len(warns)} warning(s) found:')}")
        for r in problems:
            print(f"  {STATUS_ICONS[r.status]} {r.name}" + (f" — {r.detail}" if r.detail else ""))
        advice = [r.advice for r in problems if r.advice]
        if advice:
            print()
            print(bold("  What you can do:"))
            for a in advice:
                print(f"  {yellow('→')} {a}")

    def to_dict(self):
        return {"results": [asdict(r) for r in self.results]}


def print_result(r: CheckResult):
    icon = STATUS_ICONS.get(r.status, " ")
    line = f"  {icon} {r.name}"
    if r.detail:
        line += dim(f"  {r.detail}")
    print(line)
    sys.stdout.flush()
