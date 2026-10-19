//! Decode outcome classes and their mapping to process exit codes.
//!
//! A decode attempt is reduced to exactly one of five outcomes. They are
//! distinguished by whether a baseline OTI could be established, whether the
//! derived layout stays within the format's bounds, whether every block was
//! solved, and whether the final BLAKE3 check passed.
//!
//! ## Classification order
//!
//! Signals are evaluated in the order below; the first match wins:
//!
//! | Step | Condition                     | Outcome                    | Exit code |
//! |------|-------------------------------|----------------------------|-----------|
//! | 0    | argument or I/O failure       | handled by the CLI layer   | 1         |
//! | 1    | no baseline OTI               | [`DecodeOutcome::NoOti`]   | 3         |
//! | 2    | layout violates format bounds | [`DecodeOutcome::Malformed`] | 1       |
//! | 3    | some block remains unsolved   | [`DecodeOutcome::Insufficient`] | 2   |
//! | 4    | BLAKE3 mismatch               | [`DecodeOutcome::HashMismatch`] | 4   |
//! | 5    | otherwise                     | [`DecodeOutcome::Ok`]      | 0         |
//!
//! Argument and I/O failures are reported by the CLI before the engine runs,
//! so they are not represented by [`DecodeOutcome`].

/// The outcome of a decode attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeOutcome {
    /// A baseline OTI was established, every `NB` block was solved, and either
    /// BLAKE3 verification passed or verification was disabled.
    Ok,
    /// No metadata packet yielded a baseline OTI: none was usable because it
    /// was missing, entirely corrupt, or structurally invalid.
    NoOti,
    /// A baseline OTI was established, but the layout derived from `(F, T, NB)`
    /// violates the format's layout bounds, or cannot be represented without
    /// overflow.
    Malformed,
    /// A baseline OTI was established and the layout is valid, but some blocks
    /// remained unsolved when the stream ended. This covers both insufficient
    /// symbols and solver failure.
    Insufficient,
    /// Every block was solved, but the BLAKE3 digest did not match. This
    /// outcome does not occur when verification is skipped.
    HashMismatch,
}

impl DecodeOutcome {
    /// Return the process exit code for this outcome.
    ///
    /// `Ok` maps to 0, `Malformed` to 1, `Insufficient` to 2, `NoOti` to 3, and
    /// `HashMismatch` to 4.
    pub fn exit_code(self) -> u8 {
        match self {
            DecodeOutcome::Ok => 0,
            DecodeOutcome::Malformed => 1,
            DecodeOutcome::Insufficient => 2,
            DecodeOutcome::NoOti => 3,
            DecodeOutcome::HashMismatch => 4,
        }
    }
}

/// Final verification state. Verification is skipped when `--no-verify` is set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verify {
    /// Verification ran: `true` means the BLAKE3 digest matched, `false` means
    /// it did not.
    Verified(bool),
    /// Verification was skipped, so data integrity is unknown.
    Skipped,
}

/// Engine signals used to classify a decode attempt.
///
/// The engine fills these in after scanning the stream and solving the blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeSignals {
    /// Whether a baseline OTI was established.
    pub baseline_oti: bool,
    /// Whether the layout derived from `(F, T, NB)` violates the format's
    /// layout bounds.
    pub layout_malformed: bool,
    /// Whether any block remained unsolved when the stream ended.
    pub insufficient: bool,
    /// Final verification state.
    pub verify: Verify,
}

/// Classify engine signals into exactly one outcome.
///
/// The checks are applied in the order given by [`DecodeOutcome`]: a missing
/// baseline OTI takes precedence over a malformed layout, which takes
/// precedence over unsolved blocks, which takes precedence over a verification
/// mismatch. This function is a classification helper only; it does not scan or
/// solve the stream.
pub fn classify(signals: DecodeSignals) -> DecodeOutcome {
    if !signals.baseline_oti {
        return DecodeOutcome::NoOti;
    }
    if signals.layout_malformed {
        return DecodeOutcome::Malformed;
    }
    if signals.insufficient {
        return DecodeOutcome::Insufficient;
    }
    match signals.verify {
        Verify::Skipped | Verify::Verified(true) => DecodeOutcome::Ok,
        Verify::Verified(false) => DecodeOutcome::HashMismatch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signals() -> DecodeSignals {
        DecodeSignals {
            baseline_oti: true,
            layout_malformed: false,
            insufficient: false,
            verify: Verify::Verified(true),
        }
    }

    #[test]
    fn five_classes_and_exit_codes() {
        assert_eq!(classify(signals()), DecodeOutcome::Ok);
        assert_eq!(
            classify(DecodeSignals {
                baseline_oti: false,
                insufficient: true,
                ..signals()
            }),
            DecodeOutcome::NoOti,
            "missing baseline OTI takes precedence over all later checks"
        );
        assert_eq!(
            classify(DecodeSignals {
                layout_malformed: true,
                insufficient: true,
                ..signals()
            }),
            DecodeOutcome::Malformed,
            "Malformed takes precedence over Insufficient"
        );
        assert_eq!(
            classify(DecodeSignals {
                insufficient: true,
                verify: Verify::Verified(false),
                ..signals()
            }),
            DecodeOutcome::Insufficient,
            "Insufficient takes precedence over HashMismatch"
        );
        assert_eq!(
            classify(DecodeSignals {
                verify: Verify::Verified(false),
                ..signals()
            }),
            DecodeOutcome::HashMismatch
        );
        assert_eq!(
            classify(DecodeSignals {
                verify: Verify::Skipped,
                ..signals()
            }),
            DecodeOutcome::Ok,
            "HashMismatch is never produced with --no-verify"
        );

        assert_eq!(DecodeOutcome::Ok.exit_code(), 0);
        assert_eq!(DecodeOutcome::Malformed.exit_code(), 1);
        assert_eq!(DecodeOutcome::Insufficient.exit_code(), 2);
        assert_eq!(DecodeOutcome::NoOti.exit_code(), 3);
        assert_eq!(DecodeOutcome::HashMismatch.exit_code(), 4);
    }
}
