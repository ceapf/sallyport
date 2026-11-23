# Try it: a scripted session, by hand

This walks through `sallyd` running a session whose model is a script instead of an LLM. Each
turn of the script is one step you ask for with `sally session drive`. The tool calls a turn
names go through the same policy, approvals and audit entries as a harness's calls would. The
script is data: it can name calls and say things, nothing more.

Everything below runs on Linux or WSL2 with rootless Podman 4.9 or newer and cgroup v2. Paths
use `~`; `<id>`, `<digest>` and `<hash>` stand for values your run prints.

## 1. Build and check the host

From the repository root:

```sh
cargo build -p sallyd -p sally-cli
export PATH="$PWD/target/debug:$PATH"
sally doctor
```

Every line of `sally doctor` should read `PASS`. A `FAIL` names what to fix first.

## 2. An image for the workspace

`sallyd` has no bundled workspace image yet (TODO(#88)), so a manifest must name one by digest.
Use the developer test image the container tests build. It is **not a product image**: it
carries the red-team probe and an entry that idles.

```sh
podman pull docker.io/library/alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
cargo test -q -p sallyd --test session rt_drv_01
podman images --format '{{.Repository}}:{{.Tag}} {{.Digest}}' | grep sallyport-test:local
```

The test, run on its own (not through `scripts/test-run.sh`), builds
`localhost/sallyport-test:local-<hash>`, which is kept for later runs. The last command prints
its digest, `sha256:<digest>`.

## 3. Start the daemon

In a terminal of its own (terminal 1):

```sh
sallyd
```

It logs to stderr and serves `control.sock` under `$XDG_RUNTIME_DIR/sallyport/`. Ctrl-C stops it
and every session.

## 4. A manifest and a script

Make a folder for the session to work in, and two files anywhere, say in `~/try-it/`:

```sh
mkdir -p ~/code/try-it ~/try-it
```

`~/try-it/m.yaml`, with your digest:

```yaml
apiVersion: sallyport/v1
kind: Manifest
name: try-it
runtime:
  image: localhost/sallyport-test@sha256:<digest>
model:
  ref: any
filesystem:
  mounts:
    - host: "~/code/try-it"
      guest: /workspace/p
      mode: rw
tools:
  builtin: [fs_list, shell]
  shell: approve
```

`~/try-it/s.jsonl`, one turn per line:

```json
{"tool_calls":[{"name":"fs_list","arguments":{"path":"/workspace/p"}}]}
{"tool_calls":[{"name":"shell","arguments":{"cmd":["touch","/workspace/p/hello"],"cwd":"/workspace/p"}}]}
{"content":"done: made /workspace/p/hello"}
```

A line is a `content` message, a `tool_calls` list (at most 8 calls) or `{"fail":true}`. A
driven script ends at its first `content` or `fail` line; one with lines after it is refused.

Read what the manifest allows before you start anything:

```sh
cd ~/try-it
sally manifest summary m.yaml
```

It names the folder, says shell commands need your approval and that there is no network.
Its last line is `sha256 <hex>`, the hash of the text it read.

Every launch from a manifest needs your consent. In a terminal, `sally session start` and
`sally sandbox run` print the summary again and ask
`Start a session with this manifest? Type yes to start:`; type `yes` (each launch below asks).
Off a terminal (input piped in, a script) pass `--accept-manifest <hex>` with that hash
instead; a hash of any other text refuses. Never use a hash that came with a manifest.

## 5. Drive it with nobody to approve

```sh
sally session start m.yaml --script s.jsonl
```

```text
<id>  running  try-it  sp-ws-<id>  scripted, driven, 3 turns, sha256 <hash>
```

The hash is `sallyd`'s SHA-256 of the script it parsed: `sha256sum s.jsonl` prints the same.

```sh
sally session drive <id>
```

```text
turn 1: call fs_list -> {"entries":[],"path":"/workspace/p","truncated":false,"unlisted":0}
turn 2: call shell -> denied: no-approver
turn 3: model says: done: made /workspace/p/hello
```

Nobody was watching for prompts, so the shell call was denied and `~/code/try-it` is still
empty. Turn 3 says otherwise: a model's message is only text. Stop the session:

```sh
sally session stop <id>
```

## 6. Drive it with an approver

In a second terminal (terminal 2), start the approver. It reads answers from the terminal only,
never from a pipe:

```sh
sally approve
```

In your first shell, start a fresh session (each session's script runs once) and drive it:

```sh
sally session start m.yaml --script s.jsonl
sally session drive <id>
```

Turn 2 waits. Terminal 2 shows the exact command and asks:

```text
approval ap-<…> (session <id>, call 1)
  action: run ["touch" "/workspace/p/hello"] in "/workspace/p"
  digest: <…>
approve, deny or deny-all?
```

Type `approve`. The drive goes on:

```text
turn 2: call shell -> {"exit":0,"killed":null,"stderr":"","stderr_cut":false,"stdout":"","stdout_cut":false}
turn 3: model says: done: made /workspace/p/hello
```

`ls ~/code/try-it` now shows `hello`. Answer `deny` instead and turn 2 reads
`call shell -> denied: denied`, and nothing is made.

The terminal that runs `sally session drive` never asks you anything: anything there that looks
like a prompt is the script's text, escaped.

## 7. Read the audit trail

```sh
sally session list
sally session stop <id>
sally audit tail -n 16
sally audit verify
```

The session's entries for the call are actor `driver`, never `harness`: `drive.turn`,
`rpc.request`, `tool.pending`, `tool.run`; the approval is `user`. A turn's entry holds the
message's size and hash, never its text. `sally audit verify` checks the whole hash chain.

## 8. Line mode: run one command

`sally sandbox run` starts a session of a manifest, runs one command in its workspace, relays
your stdin to it and its output to you, then stops the session. No script and no approver are
involved: you typed the command. The session lives as long as the connection: Ctrl-C, or a
closed terminal, kills the command and stops the session (reason `disconnect`).

```sh
cd ~/try-it
sally sandbox run --manifest m.yaml -- sh -c 'echo hi; ls /workspace/p'
echo "exit: $?"
```

```text
hi
hello
exit: 0
```

Stdin reaches the command as UTF-8 text, and its exit code is yours. Piped input is not a
terminal, so this launch takes the hash `sally manifest summary m.yaml` printed:

```sh
printf 'one\ntwo\n' | sally sandbox run --manifest m.yaml --accept-manifest <hex> -- sh -c 'cat; exit 3'
echo "exit: $?"
```

```text
one
two
exit: 3
```

Output is shown as printable ASCII and newlines: an escape sequence the sandbox prints cannot
colour, retitle, link or rewrite your terminal.

```sh
sally sandbox run --manifest m.yaml -- printf '\033[31mred\033]52;c;eA==\007\r\n'
```

```text
\x1b[31mred\x1b]52;c;eA==\x07\x0d
```

Anything there that looks like a prompt, or like a `sally:` line, is the command's output. The
exit status and `sally audit tail` are what to trust: the session's log holds `sandbox.exec`
(the command, actor `user`) and `sandbox.exec_result` (how it ended and the byte counts, never
the bytes). A command that `sallyd` killed exits 137 with one `sally: the command was killed: …`
line. Stdin that is not UTF-8 ends the run (`sally: stdin is not UTF-8 text; the command was
ended`). There is no terminal mode yet (`--tty` is refused as an unknown flag).

## 9. What is refused

```sh
sally session start m.yaml                  # no script: an ordinary session
sally session drive <id>                    # sally: refused: not-driven
sally session stop <id>
printf '{"content":"hi"}\n{"fail":true}\n' > dead.jsonl
sally session start m.yaml --script dead.jsonl
# sally: refused: script-invalid: model.script turn 2: follows a content or fail turn, ...
```

A second connection cannot drive a session another one drives (`driver-busy`), and once the
driving connection has closed nobody can (`driver-gone`). The driving connection is never an
approver: `approvals.decide` on it is refused `driver-seat`.

## 10. Clean up

Ctrl-C in terminal 1 stops `sallyd`. Remove `~/code/try-it` and `~/try-it` when you are done.
The test image stays cached; `podman image rm localhost/sallyport-test:local-<hash>` removes it.
