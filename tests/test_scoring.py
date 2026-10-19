import pytest

from header_auditor.models import Finding, Severity
from header_auditor.scoring import grade, score


def findings(*sevs):
    return [Finding("X", s, "t") for s in sevs]


def test_perfect_score():
    assert score(findings(Severity.PASS, Severity.INFO)) == 100


def test_penalties_add_up():
    assert score(findings(Severity.HIGH, Severity.MEDIUM, Severity.LOW)) == 65


def test_score_never_negative():
    assert score(findings(*[Severity.HIGH] * 10)) == 0


@pytest.mark.parametrize(
    ("points", "letter"),
    [
        (100, "A+"),
        (95, "A+"),
        (94, "A"),
        (85, "A"),
        (70, "B"),
        (55, "C"),
        (40, "D"),
        (39, "F"),
        (0, "F"),
    ],
)
def test_grades(points, letter):
    assert grade(points) == letter
