"""Every output recorded by examples/readme_examples.sh must appear in README.md."""

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
EX = ROOT / "examples"
OUTS = sorted((EX / "out").glob("*.txt"))
README = (ROOT / "README.md").read_text(encoding="utf-8")


def test_outputs_exist():
    assert {p.stem for p in OUTS} == {"server", "docker-user", "fixed"}


@pytest.mark.parametrize("path", OUTS, ids=lambda p: p.stem)
def test_recorded_output_is_in_readme(path):
    body, code_line = path.read_text(encoding="utf-8").rstrip("\n").rsplit("\n", 1)
    assert code_line.startswith("exit ")
    assert body + "\n$ echo $?\n" + code_line.split()[1] in README, (
        f"README is missing the output of {path.name}; re-run examples/readme_examples.sh and update README")


def test_excerpt_is_from_the_example_and_shown():
    excerpt = (EX / "server" / "README-excerpt.txt").read_text(encoding="utf-8")
    assert excerpt.rstrip() in README
    full = (EX / "server" / "iptables-save.txt").read_text(encoding="utf-8").splitlines()
    for line in excerpt.splitlines():
        if line != "...":
            assert line in full, line
