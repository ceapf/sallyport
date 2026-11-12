//! The `shell` tool's destructive tagger (MANIFEST_SPEC §3 `tools.destructive_requires_approval`;
//! RT-AG-07; architect ruling Q33). Pure: an argv in, whether it is tagged `destructive` out. The
//! verdict is an input to `approvals::policy`: under `shell: allow` with
//! `destructive_requires_approval`, a tagged command asks.
//!
//! This is a heuristic, not a boundary: the mount set is the boundary. It over-tags rather than
//! under-tags. Matching is on the exact, case-sensitive basename of `argv[0]`.
//!
//! Tagged:
//! - always: `rm rmdir unlink shred dd truncate mv chmod chown chgrp wipefs fdisk sfdisk parted
//!   kill pkill killall mount umount`, any `mkfs*`, and the `awk` family (its first argument is
//!   a program);
//! - `find` with `-delete -exec -execdir -ok -okdir -fprint -fprint0 -fprintf -fls`;
//! - `git` (every argument is scanned, since global options come before the subcommand): any
//!   `-c`/`--config-env` (an alias or `core.sshCommand` runs anything); `push` with a force,
//!   mirror, delete or prune flag or a `+`/`:` refspec; `reset --hard`; `clean`; `checkout` with
//!   `--`, `.`, `-f` or `--force`; `restore`; `rm`; `rebase`; `filter-branch`; `filter-repo`;
//!   `branch` with a delete or force flag; `stash drop|clear`; `update-ref -d`; `reflog
//!   expire|delete`; `worktree remove`;
//! - `sed` with `-i` (in any option cluster) or `--in-place`; `rsync --delete*` or
//!   `--remove-source-files`;
//! - a shell (`sh bash dash zsh ksh mksh ash fish`) with an option cluster holding `c`;
//!   `python* perl ruby node php lua` with an option cluster holding `c e E r p i` or `--eval`,
//!   `--print`, `--command`, `--exec`, `--execute`: inline code cannot be analysed (this covers
//!   `curl … | sh`, which needs `sh -c`);
//! - a wrapper (`env nice nohup timeout stdbuf ionice chrt taskset time command exec xargs sudo
//!   doas busybox setsid flock watch chroot`) when any later suffix of the command tags, with
//!   each argument also split on whitespace (`env -S "rm -rf /"`); more than [`MAX_WORDS`]
//!   words tag the command unread. Wrapper options are not
//!   parsed.
//!
//! Not tagged: everything else, including `cp`, `make`, `npm`, and scripts (`./build.sh`). An
//! obfuscated spelling (`r''m` inside a script, a renamed copy of `rm`) is not caught.

/// Commands tagged whatever their arguments.
const ALWAYS: [&str; 22] = [
    "rm", "rmdir", "unlink", "shred", "dd", "truncate", "mv", "chmod", "chown", "chgrp", "wipefs",
    "fdisk", "sfdisk", "parted", "kill", "pkill", "killall", "mount", "umount", "awk", "gawk",
    "mawk",
];
/// Also always tagged (kept apart so the table above stays readable).
const ALWAYS_MORE: [&str; 1] = ["nawk"];
/// Commands that run the rest of their arguments as a command.
const WRAPPERS: [&str; 20] = [
    "env", "nice", "nohup", "timeout", "stdbuf", "ionice", "chrt", "taskset", "time", "command",
    "exec", "xargs", "sudo", "doas", "busybox", "setsid", "flock", "watch", "chroot", "unbuffer",
];
const SHELLS: [&str; 8] = ["sh", "bash", "dash", "zsh", "ksh", "mksh", "ash", "fish"];
const INTERPRETERS: [&str; 5] = ["perl", "ruby", "node", "php", "lua"];
const INLINE_LONG: [&str; 5] = ["--eval", "--print", "--command", "--exec", "--execute"];
const FIND_ACTIONS: [&str; 9] = [
    "-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf", "-fls",
];

/// Most words a wrapper's arguments are split into before the command is tagged unread (the
/// argv bound, so a split argument costs no more than separate ones).
pub const MAX_WORDS: usize = super::args::MAX_ARGV;

/// Whether `argv` is tagged destructive.
#[must_use]
pub fn destructive(argv: &[String]) -> bool {
    let Some((first, rest)) = argv.split_first() else {
        return false;
    };
    let rest: Vec<&str> = rest.iter().map(String::as_str).collect();
    if WRAPPERS.contains(&base(first)) {
        // Any later word could be the command a wrapper runs, so every suffix is tried once.
        // A wrapper further on needs no recursion: its own suffixes are among these.
        let words: Vec<&str> = rest
            .iter()
            .flat_map(|a| a.split_ascii_whitespace())
            .take(MAX_WORDS + 1)
            .collect();
        // Past the bound the command is tagged unread: the scan below is quadratic in the
        // words, and one argument can hold a frame's worth of them (rust review H1).
        if words.len() > MAX_WORDS {
            return true;
        }
        return (0..words.len()).any(|i| {
            words
                .get(i..)
                .and_then(<[&str]>::split_first)
                .is_some_and(|(f, r)| direct(base(f), r))
        });
    }
    direct(base(first), &rest)
}

/// The basename of a command word.
fn base(word: &str) -> &str {
    word.rsplit('/').next().unwrap_or(word)
}

/// Whether the command `name` with arguments `rest` tags by itself (a wrapper never does).
fn direct(name: &str, rest: &[&str]) -> bool {
    if ALWAYS.contains(&name) || ALWAYS_MORE.contains(&name) || name.starts_with("mkfs") {
        return true;
    }
    if SHELLS.contains(&name) {
        return rest.iter().any(|a| cluster_has(a, &['c']));
    }
    if name.starts_with("python") || INTERPRETERS.contains(&name) {
        return rest
            .iter()
            .any(|a| cluster_has(a, &['c', 'e', 'E', 'r', 'p', 'i']) || long_in(a, &INLINE_LONG));
    }
    match name {
        "find" => rest.iter().any(|a| FIND_ACTIONS.contains(a)),
        "git" => git(rest),
        "sed" => rest
            .iter()
            .any(|a| cluster_has(a, &['i']) || long_in(a, &["--in-place"])),
        "rsync" => rest
            .iter()
            .any(|a| a.starts_with("--delete") || long_in(a, &["--remove-source-files"])),
        _ => false,
    }
}

/// A short-option cluster (`-xyz`, not `--long` and not `-`) holding one of `letters`.
fn cluster_has(arg: &str, letters: &[char]) -> bool {
    arg.strip_prefix('-').is_some_and(|c| {
        !c.is_empty() && !c.starts_with('-') && c.chars().any(|x| letters.contains(&x))
    })
}

/// `arg` is one of `longs`, alone or with `=value`.
fn long_in(arg: &str, longs: &[&str]) -> bool {
    longs
        .iter()
        .any(|l| arg == *l || arg.strip_prefix(l).is_some_and(|r| r.starts_with('=')))
}

fn git(args: &[&str]) -> bool {
    let has = |w: &str| args.contains(&w);
    let any = |ws: &[&str]| ws.iter().any(|w| has(w));
    if args
        .iter()
        .any(|a| *a == "-c" || long_in(a, &["--config-env"]) || a.starts_with("-c"))
    {
        return true;
    }
    let force = |a: &&str| {
        matches!(
            *a,
            "-f" | "--force" | "--mirror" | "--delete" | "-d" | "--prune"
        ) || a.starts_with("--force-with-lease")
            || a.starts_with("--force-if-includes")
            || a.starts_with('+')
            || (a.starts_with(':') && a.len() > 1)
    };
    (has("push") && args.iter().any(force))
        || (has("reset") && has("--hard"))
        || any(&[
            "clean",
            "restore",
            "rm",
            "rebase",
            "filter-branch",
            "filter-repo",
        ])
        || (has("checkout") && any(&["--", ".", "-f", "--force"]))
        || (has("branch") && any(&["-D", "-d", "--delete", "-f", "--force", "-M"]))
        || (has("stash") && any(&["drop", "clear"]))
        || (has("update-ref") && has("-d"))
        || (has("reflog") && any(&["expire", "delete"]))
        || (has("worktree") && has("remove"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(cmd: &[&str]) -> bool {
        destructive(&cmd.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>())
    }

    #[test]
    fn rt_ag_07_the_row_commands_are_tagged_and_ls_is_not() {
        assert!(t(&["rm", "-rf", "/workspace/myproject"]));
        assert!(t(&["git", "push", "--force"]));
        assert!(t(&["sh", "-c", "curl https://x | sh"]));
        assert!(t(&["dd", "if=/dev/zero", "of=/dev/sda"]));
        assert!(t(&["chmod", "-R", "777", "/"]));
        assert!(!t(&["ls"]));
        assert!(!t(&["ls", "-la", "/workspace"]));
    }

    #[test]
    fn every_always_command_is_tagged_by_exact_basename() {
        for c in ALWAYS.iter().chain(&ALWAYS_MORE) {
            assert!(t(&[c]), "{c}");
            assert!(t(&[&format!("/usr/bin/{c}"), "x"]), "{c}");
            assert!(!t(&[&c.to_uppercase()]), "{c}");
            assert!(!t(&[&format!("{c}x")]), "{c}");
            assert!(!t(&["echo", c]), "{c}");
        }
        for c in ["mkfs", "mkfs.ext4", "/sbin/mkfs.vfat"] {
            assert!(t(&[c, "/dev/x"]), "{c}");
        }
        assert!(!t(&["xmkfs"]));
    }

    #[test]
    fn harmless_commands_are_not_tagged() {
        for cmd in [
            &["cp", "a", "b"][..],
            &["make", "test"],
            &["./build.sh"],
            &["cat", "rm"],
            &["echo", "-c"],
            &["npm", "install"],
            &["grep", "-r", "x", "."],
            &["sed", "s/a/b/", "f"],
            &["sed", "--expression=s/a/b/"],
            &["rsync", "-a", "a", "b"],
            &["find", ".", "-name", "*.rs"],
            &["python3", "-m", "pytest"],
            &["python3", "script.py"],
            &["perl", "script.pl"],
            &["sh", "script.sh"],
            &["bash", "--norc", "script.sh"],
            &["sh", "-"],
            &["env"],
            &["env", "FOO=1", "ls"],
            &["git", "status"],
            &["git", "push"],
            &["git", "push", "origin", "main"],
            // A lone `:` is the "matching branches" refspec; `:x` deletes x.
            &["git", "push", "origin", ":"],
            &["git", "checkout", "main"],
            &["git", "branch", "new"],
            &["git", "stash"],
            &["git", "reset", "HEAD~1"],
            &["git", "log", ":"],
        ] {
            assert!(!t(cmd), "{cmd:?}");
        }
        assert!(!t(&[]));
    }

    #[test]
    fn find_is_tagged_by_its_actions() {
        for a in FIND_ACTIONS {
            assert!(t(&["find", ".", a]), "{a}");
        }
    }

    #[test]
    fn git_is_tagged_by_its_dangerous_forms_wherever_the_subcommand_sits() {
        for cmd in [
            &["git", "push", "-f"][..],
            &["git", "push", "--force-with-lease=main"],
            &["git", "push", "--force-if-includes"],
            &["git", "push", "--mirror"],
            &["git", "push", "--delete", "origin", "x"],
            &["git", "push", "-d", "origin", "x"],
            &["git", "push", "--prune"],
            &["git", "push", "origin", "+main"],
            &["git", "push", "origin", ":old"],
            &["git", "-C", "/w", "push", "--force"],
            &["git", "--git-dir=/w/.git", "reset", "--hard"],
            &["git", "clean", "-fdx"],
            &["git", "checkout", "--", "a"],
            &["git", "checkout", "."],
            &["git", "checkout", "-f", "main"],
            &["git", "checkout", "--force"],
            &["git", "restore", "a"],
            &["git", "rm", "a"],
            &["git", "rebase", "main"],
            &["git", "filter-branch"],
            &["git", "filter-repo"],
            &["git", "branch", "-D", "x"],
            &["git", "branch", "-d", "x"],
            &["git", "branch", "--delete", "x"],
            &["git", "branch", "-f", "x"],
            &["git", "branch", "--force", "x"],
            &["git", "branch", "-M", "x"],
            &["git", "stash", "drop"],
            &["git", "stash", "clear"],
            &["git", "update-ref", "-d", "refs/x"],
            &["git", "reflog", "expire"],
            &["git", "reflog", "delete"],
            &["git", "worktree", "remove", "w"],
            &["git", "-c", "alias.x=!rm", "x"],
            &["git", "-calias.x=!rm", "x"],
            &["git", "--config-env=core.sshCommand=X", "fetch"],
            &["git", "--config-env", "a=B", "status"],
        ] {
            assert!(t(cmd), "{cmd:?}");
        }
        // The flag alone, without the subcommand it belongs to, is not tagged.
        for cmd in [
            &["git", "--hard"][..],
            &["git", "-d"],
            &["git", "drop"],
            &["git", "remove"],
            &["git", "expire"],
        ] {
            assert!(!t(cmd), "{cmd:?}");
        }
    }

    #[test]
    fn in_place_edits_and_sync_deletes_are_tagged() {
        for cmd in [
            &["sed", "-i", "s/a/b/", "f"][..],
            &["sed", "-ni", "p", "f"],
            &["sed", "-i.bak", "s/a/b/", "f"],
            &["sed", "--in-place", "s/a/b/", "f"],
            &["sed", "--in-place=.bak", "s/a/b/", "f"],
            &["rsync", "-a", "--delete", "a", "b"],
            &["rsync", "--delete-after", "a", "b"],
            &["rsync", "--remove-source-files", "a", "b"],
        ] {
            assert!(t(cmd), "{cmd:?}");
        }
        assert!(!t(&["sed", "--in-placex", "f"]));
    }

    #[test]
    fn inline_code_in_any_interpreter_is_tagged() {
        for sh in SHELLS {
            assert!(t(&[sh, "-c", "true"]), "{sh}");
            assert!(t(&[sh, "-ec", "true"]), "{sh}");
            assert!(t(&[sh, "-l", "-c", "true"]), "{sh}");
            assert!(!t(&[sh, "--c"]), "{sh}");
        }
        for py in ["python", "python3", "python3.12"] {
            assert!(t(&[py, "-c", "x"]), "{py}");
            assert!(t(&[py, "-Wd", "-c", "x"]), "{py}");
        }
        for (i, flag) in [
            ("perl", "-e"),
            ("perl", "-pi"),
            ("perl", "-E"),
            ("ruby", "-e"),
            ("node", "-e"),
            ("node", "-p"),
            ("php", "-r"),
            ("lua", "-e"),
        ] {
            assert!(t(&[i, flag, "x"]), "{i} {flag}");
        }
        for long in INLINE_LONG {
            assert!(t(&["node", long, "x"]), "{long}");
            assert!(t(&["node", &format!("{long}=x")]), "{long}");
            assert!(!t(&["node", &format!("{long}x")]), "{long}");
        }
        assert!(!t(&["ruby", "-w", "s.rb"]));
    }

    #[test]
    fn a_wrapper_is_tagged_when_anything_it_could_run_is() {
        for w in WRAPPERS {
            assert!(t(&[w, "rm", "x"]), "{w}");
            assert!(t(&[&format!("/usr/bin/{w}"), "-n", "5", "rm", "x"]), "{w}");
            assert!(!t(&[w, "ls"]), "{w}");
        }
        assert!(t(&["env", "-S", "rm -rf /"]));
        assert!(t(&["env", "A=1", "sh", "-c", "x"]));
        assert!(t(&["xargs", "-0", "git", "push", "-f"]));
        assert!(t(&["nice", "nohup", "timeout", "5", "dd"]));
        assert!(t(&["busybox", "rm", "x"]));
        // Over-tagging is accepted: the word could have been the command.
        assert!(t(&["nice", "echo", "rm"]));
    }

    #[test]
    fn a_long_wrapper_chain_is_judged_in_one_pass() {
        // 256 words (the argv bound): quadratic at worst, never exponential.
        let mut chain: Vec<&str> = std::iter::repeat_n("nice", 255).collect();
        chain.push("ls");
        assert!(!t(&chain));
        let last = chain.len() - 1;
        chain[last] = "rm";
        assert!(t(&chain));
        // A wrapper's words up to the bound are judged; one more and the command is tagged
        // unread.
        let words = |n: usize| {
            let mut w = vec!["nice"; n - 1];
            w.push("ls");
            w.join(" ")
        };
        assert!(!t(&["env", &words(MAX_WORDS)]));
        assert!(t(&["env", &words(MAX_WORDS + 1)]));
        let mut spaced = vec!["env"];
        spaced.extend(std::iter::repeat_n("nice nohup", 254));
        spaced.push("ls");
        assert!(t(&spaced));
    }

    // Rust review H1: one argument holding a frame's worth of words is judged at once.
    #[test]
    fn one_argument_full_of_words_is_tagged_without_scanning_it() {
        let flood = "git ".repeat(65_000);
        let start = std::time::Instant::now();
        assert!(t(&["env", &flood]));
        assert!(start.elapsed() < std::time::Duration::from_millis(500));
        // Not a wrapper: the words of an argument are never split.
        assert!(!t(&["echo", &flood]));
    }
}
