//! The search of a running container for material that must never reach it (RT-SEC-10's key
//! search, moved here for RT-SEC-01 and RT-SEC-02: architect ruling A6). A shell script plants
//! positive controls, then prints what holds a pattern: files outside `/proc`, `/sys` and
//! `/dev`, files in `/dev/shm`, and every `/proc/*/environ` and `/proc/*/cmdline` but the
//! search's own.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

/// The positive controls a search plants before it looks.
pub struct Plants<'a> {
    /// Shell lines that write the planted files.
    pub files: &'a str,
    /// What the `/dev/shm` tripwire tries to write there: `/dev/shm` is read-only in both
    /// sandboxes, so nothing can be planted; if that ever changes the script says so, and the
    /// test fails until a plant there is added.
    pub shm: &'a str,
    /// The value planted in a process environment (`SP_PLANTED`) and a process command line.
    pub process: &'a str,
}

/// Where a search looks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Files: everything outside `/proc`, `/sys` and `/dev`, and `/dev/shm`.
    Files,
    /// Process environments and command lines.
    Procs,
    /// Both.
    All,
}

/// A shell script that plants `plants`, then prints every place in `scope` that holds one of
/// the patterns `patterns` sets (a shell fragment ending in `set -- -e … -e …`, fixed strings
/// for `grep -F`; it must include `mark`); `unreadable <path>` for an environment it may not
/// read. `mark` is carried in the argv of the search's own processes (its `sh -c` and every
/// `grep` it runs), whose command lines hold the patterns: a command line carrying it is
/// skipped. A `/proc` hit is labelled `<planted>` for the two planted processes and `<pid N>`
/// for any other, so a real leak never merges with the positive control (security re-review
/// M1 of Task 9a-2).
pub fn search_script(mark: &str, plants: &Plants, patterns: &str, scope: Scope) -> String {
    let Plants {
        files,
        shm,
        process,
    } = plants;
    let mut s = format!(
        "set -u\n\
         {files}\
         ( printf '%s' '{shm}' > /dev/shm/planted.pem ) 2>/dev/null \
           && echo '/dev/shm is writable: plant there as a positive control'\n\
         env SP_PLANTED='{process}' sleep 120 </dev/null >/dev/null 2>&1 &\n\
         planted_env=$!\n\
         sh -c 'sleep 120; :' planted '{process}' </dev/null >/dev/null 2>&1 &\n\
         planted_cmd=$!\n\
         sleep 1\n\
         {patterns}\n"
    );
    if scope != Scope::Procs {
        s.push_str(
            "find / \\( -path /proc -o -path /sys -o -path /dev \\) -prune -o -type f -print0 \
               2>/dev/null | xargs -0 grep -l -a -F \"$@\" 2>/dev/null\n\
             find /dev/shm -type f -print0 2>/dev/null | xargs -0 grep -l -a -F \"$@\" 2>/dev/null\n",
        );
    }
    if scope != Scope::Files {
        s.push_str(&format!(
            "label() {{ p=${{1#/proc/}}; p=${{p%%/*}}; \
               if [ \"$p\" = \"$planted_env\" ] || [ \"$p\" = \"$planted_cmd\" ]; \
               then echo '<planted>'; else echo \"<pid $p>\"; fi; }}\n\
             for e in /proc/[0-9]*/environ; do\n\
               if [ -e \"$e\" ] && ! [ -r \"$e\" ]; then echo \"unreadable $e\"; fi\n\
               if grep -q -a -F \"$@\" \"$e\" 2>/dev/null; then echo \"/proc/$(label $e)/environ\"; fi\n\
             done\n\
             for c in /proc/[0-9]*/cmdline; do\n\
               if grep -q -a -F -e '{mark}' \"$c\" 2>/dev/null; then continue; fi\n\
               if grep -q -a -F \"$@\" \"$c\" 2>/dev/null; then echo \"/proc/$(label $c)/cmdline\"; fi\n\
             done\n"
        ));
    }
    s.push_str("exit 0\n");
    s
}

/// `set -- -e 'p' …` for fixed strings `patterns` (each single-quoted: none may hold `'`).
pub fn fixed_patterns(patterns: &[String]) -> String {
    let mut s = String::from("set --");
    for p in patterns {
        assert!(
            !p.contains('\'') && !p.is_empty(),
            "unquotable pattern {p:?}"
        );
        s.push_str(&format!(" -e '{p}'"));
    }
    s
}

/// A shell script that prints `unreadable <path>` for every file or directory under `dirs` the
/// container's user may not read (a directory: may not list or enter), so a file search cannot
/// pass by skipping what it may not open (Task 9b security review L3). `dirs` are the places
/// `sallyd` or the sandbox writes, where an unreadable entry would hide a leak.
pub fn unreadable_script(dirs: &[&str]) -> String {
    let dirs = dirs.join(" ");
    format!(
        "for d in {dirs}; do find \"$d\" 2>/dev/null; done | while IFS= read -r p; do\n\
           if [ -d \"$p\" ]; then [ -r \"$p\" ] && [ -x \"$p\" ] || echo \"unreadable $p\";\n\
           else [ -r \"$p\" ] || echo \"unreadable $p\"; fi\n\
         done\n\
         exit 0\n"
    )
}

/// The search's output as a sorted list of distinct lines.
pub fn found(out: &str) -> Vec<String> {
    let mut v: Vec<String> = out.lines().map(str::to_owned).collect();
    v.sort();
    v.dedup();
    v
}
