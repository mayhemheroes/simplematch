#!/usr/bin/env python3
"""Atheris fuzz harness for simplematch.

Exercises the public pattern-matching API (match / test / to_regex / Matcher)
on arbitrary input. Atheris instruments the imported simplematch module
(coverage), so libFuzzer drives the pattern compiler + matcher toward new code
paths. This mirrors the fork's original target (sm.match / sm.test) and adds
the to_regex + Matcher surface for deeper coverage.

simplematch compiles user patterns to Python regexes. A fuzzed pattern can
compile to a regex that catastrophically backtracks (ReDoS) on the subject
string. Rather than a per-input signal/timer (which interferes with Atheris's
libFuzzer coverage callbacks and zeroes recorded coverage), we bound the
worst-case regex work purely by HARD-CAPPING the input sizes: a tiny pattern
matched against a short string can only backtrack for a bounded (sub-second)
time, so no single input hangs indefinitely — and coverage is recorded normally.

Run modes (driven by the compiled launcher `test_fuzz` / `-standalone`):
  * fuzzing      — `python3 test_fuzz.py [libFuzzer args]`
  * single input — `python3 test_fuzz.py <file>` (libFuzzer runs it once)
"""
import re
import sys

import atheris

# Instrument the library under test so the fuzzer gets coverage feedback.
with atheris.instrument_imports(include=["simplematch"]):
    import simplematch as sm

# Hard caps that bound worst-case regex backtracking time (no signals needed):
# a pattern this small over a string this short cannot run away indefinitely.
_PATTERN_MAX = 16
_STRING_MAX = 64


@atheris.instrument_func
def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    pattern = fdp.ConsumeUnicodeNoSurrogates(_PATTERN_MAX)
    string = fdp.ConsumeUnicodeNoSurrogates(_STRING_MAX)

    try:
        sm.match(pattern=pattern, string=string)
        sm.test(pattern, string)
        sm.to_regex(pattern)
        m = sm.Matcher(pattern)
        m.match(string)
        m.test(string)
    except re.error:
        # simplematch compiles patterns to regexes; a malformed pattern can
        # raise re.error. That is library-defined behavior on bad input.
        pass
    except (ValueError, KeyError):
        # Type-conversion / grouping errors on pathological input are expected.
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
