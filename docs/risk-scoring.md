# Risk scoring

Every server gets a score from 0 (no known risk) to 100 (worst), and a grade from A to F.

**The score is a sorting aid, not a measurement.** It helps you decide what to look at first. Two servers with
the same score are not "equally dangerous". Always read the findings.

## Points per finding

```text
points = severity points x confidence factor
```

| Severity | Points |
|---|---|
| critical | 40 |
| high | 20 |
| medium | 8 |
| low | 3 |
| info | 0 |

| Confidence or status | Factor |
|---|---|
| confirmed (proven by behavior) | 1.0 |
| high | 1.0 |
| medium | 0.6 |
| low ("possible") | 0 |

- **Possible findings score 0.** A low confidence finding is a weak signal. It is listed, so you can look, but
  it does not move the grade.
- **Repeats count a quarter, up to a cap.** The first finding of a rule counts in full. Further findings of the
  same rule count 25%, and all findings of one rule together add at most 1.5 times the first one. One kind of
  problem found in 30 tools is worse than in one tool, but not 30 times worse.
- **Not counted:** findings marked `likely-false-positive` (for example "this tool does **not** run commands")
  and findings you suppressed.

The server score is the sum, capped at 100.

## Grades

| Score | Grade | Label |
|---|---|---|
| 0 | A | No known risk |
| under 15 | B | Low risk |
| under 35 | C | Moderate risk |
| under 60 | D | High risk |
| 60 and more | F | Critical risk |

Three special cases:

- **Grade F needs strong evidence.** At least one high or critical finding must be `validated` or `confirmed`.
  Many medium-confidence findings can add up past 60, but they are still heuristics, so the score is capped at
  59 (grade D) and the report says why. Large real servers with many file and command tools often land here.
- **A confirmed malicious finding forces grade F** (score 100). Examples: a planted canary secret came back
  from a tool that did not say it returns secrets, the server wrote to `.ssh/authorized_keys`, or a package is
  a known malicious version.
- **An incomplete scan never looks safe.** When the scan failed or was partial, its score only counts what was
  checked, so it is a lower bound. A result that would be A or B becomes `?` ("unknown"). C, D, and F stay, with
  "or worse" added to the label, for example "Moderate risk or worse (the scan was not complete)".

## Why the score is what it is

Every report has a "Why this score" table: each finding that added points, its severity, its confidence, and
the math. Nothing is hidden.

## Examples

| Findings | Score | Grade |
|---|---|---|
| one high, high confidence | 20 | C |
| one high, medium confidence | 12 | B |
| one critical, low confidence | 0 | A (the finding is still listed) |
| ten highs from the same rule, high confidence | 20 + 10 (cap) = 30 | C |
| eight different high rules, all medium confidence | 59 (capped) | D |
| three highs from the same rule, high confidence | 20 + 5 + 5 = 30 | C |
| two different high rules | 40 | D |
| a confirmed canary leak | 100 | F |
