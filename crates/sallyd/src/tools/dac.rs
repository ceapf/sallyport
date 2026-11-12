//! What the sandbox's own identity may do with a file, by its mode bits (architect ruling Q39).
//! Pure. The workspace runs as `uid:gid` with no supplementary groups (`--userns=keep-id
//! --user uid:gid`), while `sallyd` keeps all of the user's groups; the file tools judge every
//! object they touch with this before they act, so the broker never does what the sandbox could
//! not (a directory shared through a supplementary group stays closed).
//!
//! The class is the owner's if `st_uid` is the sandbox uid; otherwise, for an object carrying a
//! POSIX ACL (or one whose ACL could not be read), nothing, since its group bits are the ACL mask
//! and named entries cannot be judged here; otherwise the group's if `st_gid` is the sandbox gid;
//! otherwise other's. Every wanted bit must be in that class. Not emulated: permission models
//! the mode bits do not show (NFSv4 or server-side ACLs, LSM labels); there the kernel's check
//! with `sallyd`'s credentials is the only one.

use crate::sandbox::UserIds;

/// Read.
pub const R: u32 = 4;
/// Write.
pub const W: u32 = 2;
/// Search (directories) or execute.
pub const X: u32 = 1;
/// Write and search (`W | X`): what a directory needs for an entry to be created in it or
/// removed.
pub const WX: u32 = 3;

/// The facts about an object the decision reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Object {
    /// `st_uid`.
    pub uid: u32,
    /// `st_gid`.
    pub gid: u32,
    /// `st_mode` (only the permission bits are read).
    pub mode: u32,
    /// Whether it carries an access ACL, or its ACL could not be read.
    pub acl: bool,
}

/// Whether `ids` may do `want` (a combination of [`R`], [`W`], [`X`]) with `o`.
#[must_use]
pub fn allows(o: Object, ids: UserIds, want: u32) -> bool {
    let class = if o.uid == ids.uid {
        (o.mode >> 6) & 0o7
    } else if o.acl {
        0
    } else if o.gid == ids.gid {
        (o.mode >> 3) & 0o7
    } else {
        o.mode & 0o7
    };
    want & !class == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: UserIds = UserIds {
        uid: 1000,
        gid: 100,
    };

    fn obj(uid: u32, gid: u32, mode: u32, acl: bool) -> Object {
        Object {
            uid,
            gid,
            mode,
            acl,
        }
    }

    #[test]
    fn the_owner_class_decides_for_the_owner() {
        let o = obj(1000, 5, 0o100_640, false);
        assert!(allows(o, ME, R));
        assert!(allows(o, ME, R | W));
        assert!(!allows(o, ME, X));
        assert!(!allows(o, ME, R | X));
        // The owner class rules even where group or other would allow more.
        assert!(!allows(obj(1000, 100, 0o077, false), ME, R));
        // An ACL does not take the owner's bits away.
        assert!(allows(obj(1000, 5, 0o700, true), ME, R | W | X));
    }

    #[test]
    fn the_group_class_decides_for_the_sandbox_gid_only() {
        let o = obj(0, 100, 0o750, false);
        assert!(allows(o, ME, R | X));
        assert!(!allows(o, ME, W));
        // Another group (one the user may hold as a supplementary group): other's bits.
        let shared = obj(0, 200, 0o2770, false);
        assert!(!allows(shared, ME, R));
        assert!(!allows(shared, ME, W | X));
        assert!(!allows(shared, ME, X));
        // The group class rules even where other would allow more.
        assert!(!allows(obj(0, 100, 0o707, false), ME, R));
    }

    #[test]
    fn other_bits_decide_for_everyone_else() {
        let o = obj(0, 0, 0o644, false);
        assert!(allows(o, ME, R));
        assert!(!allows(o, ME, W));
        assert!(allows(obj(0, 0, 0o711, false), ME, X));
        assert!(!allows(obj(0, 0, 0o710, false), ME, X));
        assert!(allows(obj(0, 0, 0o007, false), ME, R | W | X));
    }

    #[test]
    fn an_acl_leaves_a_non_owner_nothing() {
        assert!(!allows(obj(0, 100, 0o777, true), ME, R));
        assert!(!allows(obj(0, 0, 0o777, true), ME, X));
        assert!(allows(obj(0, 0, 0o000, true), ME, 0));
    }

    #[test]
    fn nothing_wanted_is_always_allowed_and_bits_are_r_w_x() {
        assert!(allows(obj(0, 0, 0, false), ME, 0));
        assert_eq!((R, W, X, WX), (4, 2, 1, W | X));
        // Type and set-id bits above the permission bits play no part.
        assert!(!allows(obj(0, 0, 0o107_000, false), ME, R));
        assert!(allows(obj(0, 0, 0o107_004, false), ME, R));
    }
}
