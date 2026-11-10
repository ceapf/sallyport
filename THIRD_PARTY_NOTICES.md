# Third-party notices

## Everything Claude Code (ECC)

The development-assistant configuration under `.claude/agents/`, `.claude/commands/` and
`.claude/rules/ecc/` is derived from **Everything Claude Code** v2.2.3
(<https://github.com/affaan-m/ECC>, commit `c05b2d6614f62f6db0047669aa4eefb223d478f9`).
These files configure the coding assistant used to develop Sallyport; they are not part of any
Sallyport binary.

Modifications: the `model:` frontmatter line of `build-error-resolver`, `mle-reviewer`,
`rust-build-resolver`, `rust-reviewer` and `security-reviewer` is changed to pin a model; one
sentence in `mle-reviewer` is reworded; and the example API-key strings in
`agents/code-reviewer.md` and `rules/ecc/rust/security.md` are replaced with `<hardcoded-key>` so
no literal in this repository resembles a credential. Only a subset of the upstream rules, agents
and commands is included. All other files are unmodified.

License (MIT):

```
MIT License

Copyright (c) 2026 Affaan Mustafa

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
