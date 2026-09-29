"""Print a Python file with comments, docstrings and blank lines removed.

Used by measure-integration.sh so that the exit gate's line count measures code
rather than prose. Counting prose would mean a well-documented example scored
worse than a terse one, which is an incentive nobody should have.

It uses the tokenizer rather than regexes, so a "#" inside a string is not
mistaken for a comment and a string that happens to sit in expression position
is not mistaken for a docstring.
"""

from __future__ import annotations

import io
import sys
import token
import tokenize


def main() -> None:
    source = open(sys.argv[1], "rb").read()
    drop: set[int] = set()
    previous = token.INDENT
    for tok in tokenize.tokenize(io.BytesIO(source).readline):
        if tok.type == tokenize.COMMENT:
            drop.update(range(tok.start[0], tok.end[0] + 1))
        elif tok.type == tokenize.STRING and previous in (
            token.INDENT,
            token.DEDENT,
            token.NEWLINE,
            tokenize.NL,
            tokenize.ENCODING,
        ):
            # A string in statement position is a docstring.
            drop.update(range(tok.start[0], tok.end[0] + 1))
        if tok.type not in (tokenize.NL, tokenize.COMMENT):
            previous = tok.type

    for number, line in enumerate(source.decode().splitlines(), start=1):
        if number in drop or not line.strip():
            continue
        print(line)


if __name__ == "__main__":
    main()
