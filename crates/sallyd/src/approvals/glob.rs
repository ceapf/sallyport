//! `approve.writes` / `approve.deletes` patterns (MANIFEST_SPEC §1 Mount; architect ruling Q20).
//!
//! A pattern is matched segment by segment against the canonical path relative to the mount
//! (no leading `/`, no `.`, `..` or empty segments). `**` as a whole segment matches zero or more
//! segments; `*` matches any run of characters inside one segment (dotfiles included); `?` one
//! character inside a segment. Every other character is literal; case matters. The syntax is
//! the validator's [`check_glob`]; a glob it refuses (only possible for a manifest that skipped
//! validation) is treated as `**`. Matching more means asking more, so every ambiguity resolves
//! towards a match. One glob costs at most the product of the two lengths (no backtracking), so
//! a list costs at most its total glob bytes (validator: 256 globs of 256 bytes) times
//! [`MAX_PATH`]; the path is split once per list.
//!
//! Residual: on a case-folding or normalizing file system a narrowed glob can match less than
//! the file system resolves; the default `["**"]` cannot.
#![deny(clippy::indexing_slicing)]

use sally_core::manifest::check_glob;

/// Whether any of `globs` matches `rel`.
#[must_use]
pub fn any_matches(globs: &[String], rel: &str) -> bool {
    if rel.len() > MAX_PATH {
        return true;
    }
    let path = split(rel);
    globs.iter().any(|g| matches_path(g, &path, &mut 0))
}

/// Longest relative path matched; a longer one (no file system resolves it) counts as a match, so
/// the cost of matching harness-chosen input stays bounded and the bound fails towards asking.
pub const MAX_PATH: usize = 4096;

/// Whether `glob` matches the relative path `rel`.
#[must_use]
pub fn matches(glob: &str, rel: &str) -> bool {
    matches_counting(glob, rel, &mut 0)
}

/// [`matches`], adding the inner-loop steps taken to `steps`.
fn matches_counting(glob: &str, rel: &str, steps: &mut u64) -> bool {
    if rel.len() > MAX_PATH {
        return true;
    }
    matches_path(glob, &split(rel), steps)
}

/// A path's segments, as characters.
fn split(rel: &str) -> Vec<Vec<char>> {
    rel.split('/').map(|s| s.chars().collect()).collect()
}

fn matches_path(glob: &str, path: &[Vec<char>], steps: &mut u64) -> bool {
    let Some(segments) = parse(glob) else {
        return true;
    };
    // reached[j]: the glob segments seen so far match the first `j` path segments.
    let mut reached = vec![false; path.len() + 1];
    if let Some(first) = reached.first_mut() {
        *first = true;
    }
    for g in segments {
        reached = if g == ['*', '*'] {
            // Zero or more segments: everything at or after the first reached point.
            let mut seen = false;
            reached
                .iter()
                .map(|&r| {
                    seen |= r;
                    seen
                })
                .collect()
        } else {
            // One segment: point j+1 is reached when j was and segment j matches `g`.
            std::iter::once(false)
                .chain(
                    reached
                        .iter()
                        .zip(path)
                        .map(|(&r, seg)| r && segment_matches(&g, seg, steps)),
                )
                .collect()
        };
    }
    reached.last().copied().unwrap_or(false)
}

/// The segments, as characters, of a glob the validator accepts; `None` for any other.
fn parse(glob: &str) -> Option<Vec<Vec<char>>> {
    check_glob(glob)
        .ok()
        .map(|()| glob.split('/').map(|s| s.chars().collect()).collect())
}

/// `*` (any run) and `?` (one character) inside one segment; everything else literal.
/// Each star retry moves the segment start forward once, so the loop runs at most
/// `(|glob| + 1) * (|seg| + 1)` times.
fn segment_matches(g: &[char], s: &[char], steps: &mut u64) -> bool {
    let (mut gi, mut si) = (0usize, 0usize);
    // The last `*` seen in the glob, and the segment position it was retried from.
    let mut star: Option<(usize, usize)> = None;
    while si < s.len() {
        *steps = steps.saturating_add(1);
        match (g.get(gi), s.get(si)) {
            (Some('*'), _) => {
                star = Some((gi, si));
                gi += 1;
            }
            (Some(&gc), Some(&sc)) if gc == '?' || gc == sc => {
                gi += 1;
                si += 1;
            }
            _ => match star {
                // Let the last star take one more character and retry after it.
                Some((sg, ss)) => {
                    gi = sg + 1;
                    si = ss + 1;
                    star = Some((sg, ss + 1));
                }
                None => return false,
            },
        }
    }
    g.get(gi..)
        .is_some_and(|rest| rest.iter().all(|&c| c == '*'))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn double_star_matches_everything() {
        for p in ["a", "a/b", "notes/x/y/z.md", ".git/config"] {
            assert!(matches("**", p), "{p}");
        }
    }

    #[test]
    fn a_literal_matches_only_itself() {
        assert!(matches("notes/a.md", "notes/a.md"));
        assert!(!matches("notes/a.md", "notes/b.md"));
        assert!(!matches("notes/a.md", "notes/a.md/x"));
        assert!(!matches("notes/a.md", "notes"));
        assert!(!matches("notes/a.md", "x/notes/a.md"));
    }

    #[test]
    fn a_star_stays_inside_one_segment() {
        assert!(matches("*.md", "a.md"));
        assert!(matches("*.md", ".hidden.md"));
        assert!(matches("*.md", ".md"));
        assert!(!matches("*.md", "dir/a.md"));
        assert!(matches("notes/*", "notes/a"));
        assert!(!matches("notes/*", "notes/a/b"));
        assert!(!matches("notes/*", "notes"));
        assert!(matches("a*b*c", "abc"));
        assert!(matches("a*b*c", "aXbYbZc"));
        assert!(!matches("a*b*c", "aXbYc_"));
    }

    #[test]
    fn a_question_mark_is_one_character() {
        assert!(matches("?.md", "a.md"));
        assert!(matches("?.md", "é.md"));
        assert!(!matches("?.md", ".md"));
        assert!(!matches("?.md", "ab.md"));
        assert!(!matches("a?b", "a/b"));
    }

    #[test]
    fn double_star_spans_zero_or_more_segments() {
        assert!(matches("notes/**", "notes"));
        assert!(matches("notes/**", "notes/a"));
        assert!(matches("notes/**", "notes/a/b/c"));
        assert!(!matches("notes/**", "other/a"));
        assert!(matches("**/secret.txt", "secret.txt"));
        assert!(matches("**/secret.txt", "a/b/secret.txt"));
        assert!(!matches("**/secret.txt", "a/b/secret.txt.bak"));
        assert!(matches("a/**/z", "a/z"));
        assert!(matches("a/**/z", "a/b/c/z"));
        assert!(!matches("a/**/z", "a/b/c/y"));
        assert!(matches("**/**", "a/b"));
    }

    #[test]
    fn double_star_inside_a_segment_is_refused_and_so_matches_everything() {
        for g in ["a**", "**.md", "a/b**"] {
            assert!(check_glob(g).is_err(), "{g}");
            assert!(matches(g, "x/y/z"), "{g}");
        }
    }

    #[test]
    fn a_list_matches_like_its_globs_one_by_one_and_past_the_bound_asks() {
        let globs = vec!["*.md".to_owned(), "src/**".to_owned()];
        for p in ["a.md", "src/x/y", "b.txt", "d/a.md"] {
            assert_eq!(
                any_matches(&globs, p),
                globs.iter().any(|g| matches(g, p)),
                "{p}"
            );
        }
        let long = "a".repeat(MAX_PATH + 1);
        assert!(any_matches(&["b".to_owned()], &long));
        assert!(!any_matches(&["b".to_owned()], &"a".repeat(MAX_PATH)));
    }

    #[test]
    fn a_glob_the_validator_refuses_counts_as_double_star() {
        for bad in [
            "notes/", "[ab].md", "{a,b}", "a\\*", "!a", "a//b", "./a", "a/../b", "/abs", "",
        ] {
            assert!(check_glob(bad).is_err(), "{bad}");
            assert!(matches(bad, "anything/at/all"), "{bad}");
        }
    }

    #[test]
    fn bang_and_dots_inside_a_segment_are_literal() {
        assert!(matches("a!", "a!"));
        assert!(!matches("a!", "ab"));
        assert!(matches("a..b", "a..b"));
        assert!(!matches("a..b", "axxb"));
    }

    #[test]
    fn the_work_is_bounded_by_the_product_of_the_lengths() {
        // A worst case for star retries: 128 stars between `a`s, against long runs of `a`.
        // `**/` first, so every path segment is tried against the star-heavy segment.
        let glob: String = "**/".to_owned() + &"*a".repeat(125) + "*b";
        assert!(glob.len() <= 256 && check_glob(&glob).is_ok());
        let seg = "a".repeat(255);
        let path = vec![seg.as_str(); 16].join("/");
        assert!(path.len() <= MAX_PATH);
        let mut steps = 0;
        assert!(!matches_counting(&glob, &path, &mut steps));
        let bound = (glob.len() as u64 + 1) * (path.len() as u64 + 1);
        assert!(steps > 0 && steps <= bound, "{steps} > {bound}");
    }

    #[test]
    fn a_star_retry_resumes_one_character_further_and_after_the_star() {
        let chars = |s: &str| s.chars().collect::<Vec<char>>();
        // `*b` on `aab`: star, two retries, the match: four steps exactly.
        let mut steps = 0;
        assert!(segment_matches(&chars("*b"), &chars("aab"), &mut steps));
        assert_eq!(steps, 4);
        let mut steps = 0;
        assert!(!segment_matches(&chars("*b"), &chars("aaa"), &mut steps));
        assert_eq!(steps, 4);
    }

    #[test]
    fn a_path_past_the_bound_counts_as_a_match() {
        let at = "a".repeat(MAX_PATH);
        assert!(!matches("b", &at));
        assert!(matches("b", &format!("{at}a")));
    }

    #[test]
    fn matching_is_case_sensitive() {
        assert!(!matches("Notes/**", "notes/a"));
    }

    #[test]
    fn any_matches_needs_one_match_and_an_empty_list_matches_nothing() {
        let globs = vec!["*.md".to_owned(), "docs/**".to_owned()];
        assert!(any_matches(&globs, "a.md"));
        assert!(any_matches(&globs, "docs/x/y"));
        assert!(!any_matches(&globs, "src/a.rs"));
        assert!(!any_matches(&[], "a.md"));
    }

    /// A slow, obviously correct matcher (naive recursion, no tables): the reference.
    fn reference_matches(glob: &str, rel: &str) -> bool {
        let g: Vec<&str> = glob.split('/').collect();
        let p: Vec<&str> = rel.split('/').collect();
        ref_segs(&g, &p)
    }

    fn ref_segs(g: &[&str], p: &[&str]) -> bool {
        match g.split_first() {
            None => p.is_empty(),
            Some((&"**", rest)) => (0..=p.len()).any(|k| ref_segs(rest, &p[k..])),
            Some((s, rest)) => p.split_first().is_some_and(|(h, t)| {
                let (sc, hc): (Vec<char>, Vec<char>) = (s.chars().collect(), h.chars().collect());
                ref_chars(&sc, &hc) && ref_segs(rest, t)
            }),
        }
    }

    fn ref_chars(g: &[char], p: &[char]) -> bool {
        match g.split_first() {
            None => p.is_empty(),
            Some(('*', rest)) => (0..=p.len()).any(|k| ref_chars(rest, &p[k..])),
            Some(('?', rest)) => !p.is_empty() && ref_chars(rest, &p[1..]),
            Some((c, rest)) => p.first() == Some(c) && ref_chars(rest, &p[1..]),
        }
    }

    /// A canonical path segment: never `.` or `..`.
    fn seg() -> impl Strategy<Value = String> {
        prop::string::string_regex("[ab.]{1,3}")
            .unwrap()
            .prop_filter("canonical", |s| s != "." && s != "..")
    }

    fn path() -> impl Strategy<Value = String> {
        prop::collection::vec(seg(), 1..5).prop_map(|v| v.join("/"))
    }

    fn glob_seg() -> impl Strategy<Value = String> {
        prop_oneof![
            3 => prop::string::string_regex("[ab.*?]{1,3}").unwrap(),
            1 => Just("**".to_owned()),
        ]
    }

    fn glob() -> impl Strategy<Value = String> {
        prop::collection::vec(glob_seg(), 1..5).prop_map(|v| v.join("/"))
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(4096))]

        #[test]
        fn agrees_with_the_reference_and_refused_globs_match_all(g in glob(), p in path()) {
            let want = check_glob(&g).is_err() || reference_matches(&g, &p);
            prop_assert_eq!(matches(&g, &p), want, "glob {} path {}", g, p);
        }

        #[test]
        fn the_matcher_parses_exactly_what_the_validator_accepts(g in "[ab./*?!\\[{\\\\]{0,8}") {
            let parsed = parse(&g);
            prop_assert_eq!(parsed.is_some(), check_glob(&g).is_ok(), "{}", g);
            if let Some(segs) = parsed {
                prop_assert_eq!(segs.len(), g.split('/').count());
            }
        }

        #[test]
        fn double_star_asks_for_every_path(p in path()) {
            prop_assert!(any_matches(&["**".to_owned()], &p));
        }

        #[test]
        fn adding_a_glob_never_shrinks_what_asks(
            gs in prop::collection::vec(glob(), 0..4), extra in glob(), p in path(),
        ) {
            let mut more = gs.clone();
            more.push(extra);
            prop_assert!(!any_matches(&gs, &p) || any_matches(&more, &p));
        }

        #[test]
        fn a_path_matches_itself_as_a_glob(p in path()) {
            prop_assert!(matches(&p, &p));
        }

        #[test]
        fn everything_under_a_prefix_double_star_matches(pre in path(), rest in path()) {
            let g = format!("{pre}/**");
            let under = format!("{pre}/{rest}");
            prop_assert!(matches(&g, &pre));
            prop_assert!(matches(&g, &under));
        }

        #[test]
        fn a_lone_star_matches_exactly_the_single_segment_paths(p in path()) {
            prop_assert_eq!(matches("*", &p), !p.contains('/'));
        }

        #[test]
        fn replacing_a_segment_by_a_star_still_matches(p in path(), i in 0usize..5) {
            let segs: Vec<&str> = p.split('/').collect();
            let i = i % segs.len();
            let g: Vec<&str> = segs.iter().enumerate()
                .map(|(j, s)| if j == i { "*" } else { *s }).collect();
            prop_assert!(matches(&g.join("/"), &p));
        }
    }
}
