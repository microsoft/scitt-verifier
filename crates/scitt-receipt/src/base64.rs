//! Strict base64 decoding for values carried inside a statement.
//!
//! A payload field like a build policy is often a base64 string, and what a
//! consumer needs from it is the digest of the *exact* decoded bytes. That
//! makes the decoder a security boundary rather than a convenience: any
//! tolerance here — whitespace skipped, missing padding invented, an alphabet
//! guessed — changes which bytes get hashed, and a digest computed over
//! repaired input identifies something nobody signed.
//!
//! So nothing is repaired. Input that is not exactly a well-formed encoding
//! under the alphabet the caller named is refused with a reason. The one
//! accommodation is unpadded base64url, because unpadded *is* the defined form
//! of that alphabet: reconstructing its padding is reading the encoding as
//! specified, not guessing at a malformed one.
//!
//! Which alphabet applies is always the caller's explicit choice. Sniffing it
//! from the value would mean a string of pure letters and digits decoded under
//! whichever alphabet was tried first, and the two disagree for exactly the
//! characters a sniffing rule cannot see.

/// Which base64 alphabet a value is written in.
///
/// These are distinct encodings, not styles. `+/` and `-_` map to the same
/// six-bit values, so a value written in one and decoded as the other either
/// fails loudly (the usual case, because the substituted characters are not in
/// the target alphabet) or is character-for-character identical, in which case
/// the decoded bytes are the same anyway. There is no quiet middle ground,
/// which is why naming the alphabet is safe to require.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alphabet {
    /// RFC 4648 §4: `A–Z a–z 0–9 + /`, padded to a multiple of four.
    Standard,
    /// RFC 4648 §5: `A–Z a–z 0–9 - _`, padding optional.
    UrlSafe,
}

impl Alphabet {
    /// The name this alphabet is written as on the command line and in output.
    pub fn name(self) -> &'static str {
        match self {
            Self::Standard => "base64",
            Self::UrlSafe => "base64url",
        }
    }

    /// Parse an alphabet name, refusing anything else rather than defaulting.
    ///
    /// A default here would be the sniffing this module exists to avoid, one
    /// level up: an unrecognised name almost always means the author believed
    /// they were selecting something, and silently giving them `base64` would
    /// hash bytes they did not ask for.
    pub fn parse(name: &str) -> Result<Self, String> {
        match name {
            "base64" => Ok(Self::Standard),
            "base64url" => Ok(Self::UrlSafe),
            other => Err(format!(
                "unknown encoding '{other}'; expected base64 or base64url"
            )),
        }
    }
}

/// Decode `encoded` under `alphabet`, or say precisely why it is not decodable.
///
/// Whitespace is rejected rather than stripped, including a trailing newline.
/// A value that arrived with one was either wrapped in transit or read from a
/// file that added it, and in both cases the bytes the caller is about to hash
/// are not the bytes the producer encoded. Saying so is more useful than
/// quietly hashing something different.
pub fn decode(alphabet: Alphabet, encoded: &str) -> Result<Vec<u8>, String> {
    if encoded.is_empty() {
        return Err("the value is an empty string, so there is nothing to decode".into());
    }

    if let Some(what) = first_whitespace(encoded) {
        return Err(format!(
            "the value contains {what}, which is not part of a base64 value; it is refused rather \
             than stripped, because the digest of a repaired value identifies bytes nobody encoded"
        ));
    }

    match alphabet {
        Alphabet::Standard => {
            if let Some(c) = encoded.chars().find(|c| matches!(c, '-' | '_')) {
                return Err(format!(
                    "the value contains '{c}', which belongs to the base64url alphabet, not \
                     base64; decode it as base64url"
                ));
            }
            tav_crypto::base64::base64_standard_decode(encoded)
        }
        Alphabet::UrlSafe => {
            if let Some(c) = encoded.chars().find(|c| matches!(c, '+' | '/')) {
                return Err(format!(
                    "the value contains '{c}', which belongs to the base64 alphabet, not \
                     base64url; decode it as base64"
                ));
            }
            // Translate into the standard alphabet and let one decoder own
            // every remaining rule. A second implementation would be a second
            // place for the padding and alphabet checks to disagree.
            let mut translated: String = encoded
                .chars()
                .map(|c| match c {
                    '-' => '+',
                    '_' => '/',
                    other => other,
                })
                .collect();
            match translated.len() % 4 {
                0 => {}
                2 => translated.push_str("=="),
                3 => translated.push('='),
                // One leftover character cannot be the tail of any base64
                // value: the shortest encoded unit is two characters.
                _ => {
                    return Err(
                        "the value has one character more than a whole base64url unit, so it is \
                         truncated rather than unpadded"
                            .into(),
                    )
                }
            }
            tav_crypto::base64::base64_standard_decode(&translated)
        }
    }
}

/// Name the first whitespace character, for a message that says what to fix.
fn first_whitespace(encoded: &str) -> Option<&'static str> {
    encoded.chars().find_map(|c| match c {
        '\n' => Some("a line feed"),
        '\r' => Some("a carriage return"),
        '\t' => Some("a tab"),
        ' ' => Some("a space"),
        c if c.is_whitespace() => Some("whitespace"),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_base64_round_trips_through_the_decoder() {
        // "package policy" is the shape this exists for: a build policy
        // carried as base64 inside a JSON payload.
        assert_eq!(
            decode(Alphabet::Standard, "cGFja2FnZSBwb2xpY3k=").unwrap(),
            b"package policy".to_vec()
        );
    }

    #[test]
    fn base64url_decodes_with_and_without_padding() {
        // 0xFB 0xFF encodes as "-_8=" in base64url; both forms are defined.
        let padded = decode(Alphabet::UrlSafe, "-_8=").unwrap();
        let unpadded = decode(Alphabet::UrlSafe, "-_8").unwrap();
        assert_eq!(padded, vec![0xFB, 0xFF]);
        assert_eq!(unpadded, padded);
    }

    #[test]
    fn an_alphabet_is_never_guessed_from_the_value() {
        // The whole reason the caller must name the alphabet: each value is
        // well formed under one and refused by the other, and a sniffing rule
        // would have to pick without being able to tell which was meant.
        let url_only = "-_8=";
        let standard_only = "+/8=";
        assert!(decode(Alphabet::Standard, url_only).is_err());
        assert!(decode(Alphabet::UrlSafe, standard_only).is_err());
        assert!(decode(Alphabet::UrlSafe, url_only).is_ok());
        assert!(decode(Alphabet::Standard, standard_only).is_ok());
    }

    #[test]
    fn a_wrong_alphabet_names_the_right_one_rather_than_failing_obscurely() {
        let err = decode(Alphabet::Standard, "-_8=").unwrap_err();
        assert!(err.contains("base64url"), "{err}");
    }

    #[test]
    fn whitespace_is_refused_rather_than_stripped() {
        // A wrapped or newline-terminated value decodes to the same bytes
        // under a tolerant decoder, so stripping looks harmless. It is not:
        // it makes "the digest of this field" depend on how the value was
        // transported, which is the one thing a digest must not depend on.
        for value in [
            "cGFja2FnZSBwb2xpY3k=\n",
            "cGFja2Fn ZSBwb2xpY3k=",
            "cGFja2Fn\nZSBwb2xpY3k=",
        ] {
            let err = decode(Alphabet::Standard, value).unwrap_err();
            assert!(err.contains("refused rather than stripped"), "{err}");
        }
    }

    #[test]
    fn missing_standard_padding_is_a_failure_not_a_repair() {
        // base64url may omit padding; standard base64 may not. Accepting it
        // here would erase the only structural difference between the two.
        assert!(decode(Alphabet::Standard, "cGFja2FnZSBwb2xpY3k").is_err());
    }

    #[test]
    fn a_truncated_base64url_unit_is_refused() {
        // Five characters: one whole four-character unit and a single leftover.
        // No base64 value ends that way, so this is a truncation rather than
        // the omitted padding base64url permits.
        let err = decode(Alphabet::UrlSafe, "cGFja").unwrap_err();
        assert!(err.contains("truncated"), "{err}");
    }

    #[test]
    fn an_empty_value_says_so_rather_than_decoding_to_nothing() {
        // Zero bytes has a digest, and returning it would let an empty field
        // read as a successful extraction.
        let err = decode(Alphabet::Standard, "").unwrap_err();
        assert!(err.contains("nothing to decode"), "{err}");
    }

    #[test]
    fn an_unknown_encoding_name_is_refused_rather_than_defaulted() {
        assert!(Alphabet::parse("base32").is_err());
        assert_eq!(Alphabet::parse("base64").unwrap(), Alphabet::Standard);
        assert_eq!(Alphabet::parse("base64url").unwrap(), Alphabet::UrlSafe);
    }
}
