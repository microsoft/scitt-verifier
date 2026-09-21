//! Strict base64 decoding for values carried inside a statement.
//!
//! A payload field like a build policy is often a base64 string, and what a
//! consumer needs from it is the digest of the *exact* decoded bytes. That
//! makes the decoder part of a security boundary rather than a convenience.
//!
//! The reason to be strict is not that tolerance would return wrong bytes —
//! usually it would return exactly the same bytes. It is that a digest
//! published against this claim attests to one spelling of it, and every
//! tolerance widens the set of inputs that produce that digest: a value with a
//! trailing newline, or with its padding dropped, or with spare bits set in
//! its final character, all become things the published digest vouches for.
//! Refusing keeps that set as small as the encoding allows, and a caller who
//! genuinely has a wrapped or unpadded value is better served by being told so
//! than by a silent success.
//!
//! So nothing is repaired. Input that is not exactly a well-formed encoding
//! under the alphabet the caller named is refused with a reason. The one
//! accommodation is unpadded base64url, because unpadded *is* the defined form
//! of that alphabet: reconstructing its padding is reading the encoding as
//! specified, not guessing at a malformed one. Padding that is present but
//! inconsistent is refused, because that is a repair rather than a reading.
//!
//! Which alphabet applies is always the caller's explicit choice. Sniffing it
//! from the value would mean a string of pure letters and digits decoded under
//! whichever alphabet was tried first, and the two disagree for exactly the
//! characters a sniffing rule cannot see.

use std::borrow::Cow;

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

/// The largest encoded value this will decode.
///
/// A claim is a span inside a payload that is already in memory, so this does
/// not defend the process against a large file. It bounds the *additional*
/// allocation a single `--decode` causes — the translated copy and the decoded
/// bytes — so that a payload which parsed cannot then multiply itself. The
/// limit is generous enough for the documents that appear in practice, a
/// policy or an SBOM, and a value beyond it is reported against the claim
/// rather than by an allocator failure with nothing to point at.
pub const MAX_ENCODED_LEN: usize = 32 * 1024 * 1024;

/// Decode `encoded` under `alphabet`, or say precisely why it is not decodable.
///
/// Whitespace is rejected rather than stripped, and padding that is present
/// but wrong is rejected rather than completed. Neither is a claim that a
/// tolerant decoder would return different bytes: stripping a trailing newline
/// or completing absent padding usually yields exactly the same bytes. The
/// reason to refuse is narrower. A digest published against this claim
/// identifies one spelling of it, and a decoder that accepts several spellings
/// quietly widens what that digest attests to. Refusing keeps the set of
/// inputs that produce a given digest as small as the encoding allows.
pub fn decode(alphabet: Alphabet, encoded: &str) -> Result<Vec<u8>, String> {
    if encoded.is_empty() {
        return Err("the value is an empty string, so there is nothing to decode".into());
    }

    if encoded.len() > MAX_ENCODED_LEN {
        return Err(format!(
            "the value is {} bytes of base64, above the {MAX_ENCODED_LEN} byte limit for a single \
             claim; decoding it is refused rather than attempted",
            encoded.len()
        ));
    }

    if let Some(what) = first_whitespace(encoded) {
        return Err(format!(
            "the value contains {what}, which is not part of a base64 value; it is refused rather \
             than stripped, so that a value wrapped or newline-terminated in transit cannot pass \
             for the one the producer encoded"
        ));
    }

    let standard = match alphabet {
        Alphabet::Standard => {
            if let Some(c) = encoded.chars().find(|c| matches!(c, '-' | '_')) {
                return Err(format!(
                    "the value contains '{c}', which belongs to the base64url alphabet, not \
                     base64; decode it as base64url"
                ));
            }
            Cow::Borrowed(encoded)
        }
        Alphabet::UrlSafe => {
            if let Some(c) = encoded.chars().find(|c| matches!(c, '+' | '/')) {
                return Err(format!(
                    "the value contains '{c}', which belongs to the base64 alphabet, not \
                     base64url; decode it as base64"
                ));
            }
            Cow::Owned(to_standard(encoded)?)
        }
    };

    let bytes = tav_crypto::base64::base64_standard_decode(&standard)?;
    reject_non_canonical(&standard, &bytes)?;
    Ok(bytes)
}

/// Translate base64url into the standard alphabet, supplying padding only when
/// there is none.
///
/// Unpadded is the defined form of base64url, so reconstructing padding for a
/// value that carries none is reading the encoding rather than repairing the
/// value. Padding that is *present but wrong* is a different thing: the
/// producer said where the value ends and was inconsistent about it. Topping
/// that up would be the repair this module refuses to perform, so it is an
/// error instead.
fn to_standard(encoded: &str) -> Result<String, String> {
    let mut translated: String = encoded
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();

    let pad = translated.chars().rev().take_while(|&c| c == '=').count();
    if pad > 0 {
        if translated.len() % 4 != 0 {
            return Err(format!(
                "the value ends with {pad} padding character(s) but its length is not a multiple \
                 of four, so its padding is wrong rather than absent; it is refused rather than \
                 completed"
            ));
        }
        // Well-formed padding, or padding the decoder itself will reject for
        // being misplaced. Either way it is not this function's to complete.
        return Ok(translated);
    }

    match translated.len() % 4 {
        0 => {}
        2 => translated.push_str("=="),
        3 => translated.push('='),
        // One leftover character cannot be the tail of any base64 value: the
        // shortest encoded unit is two characters.
        _ => {
            return Err(
                "the value has one character more than a whole base64url unit, so it is \
                 truncated rather than unpadded"
                    .into(),
            )
        }
    }
    Ok(translated)
}

/// Refuse a value whose final character sets bits beyond the bytes it decodes to.
///
/// The decoder ignores those bits, so `Zh==` and `Zg==` both yield `f`. That
/// makes several spellings of one value decode identically, and a digest
/// published against one of them would be attested by all of them. Comparing
/// against a re-encoding is cheaper to trust than reasoning about which bits
/// are spare in each tail length, and it reuses the encoder already present.
fn reject_non_canonical(standard: &str, bytes: &[u8]) -> Result<(), String> {
    let reencoded = tav_crypto::base64::base64_encode_no_padding(bytes);
    let normalised: String = standard
        .trim_end_matches('=')
        .chars()
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            other => other,
        })
        .collect();
    if reencoded != normalised {
        return Err(format!(
            "the value is not canonical: its final character sets bits that lie beyond the {} \
             byte(s) it decodes to, so it is one of several spellings of those bytes",
            bytes.len()
        ));
    }
    Ok(())
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
    fn padding_that_is_present_but_wrong_is_refused_rather_than_completed() {
        // `Zg=` is neither the unpadded form base64url defines nor the padded
        // form it permits. Topping it up to `Zg==` would be exactly the repair
        // this module refuses elsewhere, and it silently accepted this before.
        for wrong in ["Zg=", "Zm9vYg=", "Zg=====", "Z="] {
            let err =
                decode(Alphabet::UrlSafe, wrong).expect_err(&format!("{wrong} must be refused"));
            assert!(
                err.contains("padding") || err.contains("canonical"),
                "{wrong}: {err}"
            );
        }
        // The correctly padded and correctly unpadded spellings still work.
        assert_eq!(decode(Alphabet::UrlSafe, "Zg==").unwrap(), b"f");
        assert_eq!(decode(Alphabet::UrlSafe, "Zg").unwrap(), b"f");
    }

    #[test]
    fn a_value_with_spare_bits_set_in_its_tail_is_refused() {
        // `Zg==` and `Zh==` both decode to `f`, because the decoder ignores
        // the four bits past the end. Accepting both would mean a digest
        // published against one spelling is attested by the other.
        assert_eq!(decode(Alphabet::Standard, "Zg==").unwrap(), b"f");
        let err = decode(Alphabet::Standard, "Zh==").unwrap_err();
        assert!(err.contains("canonical"), "{err}");

        // Same at the two-byte tail, where two bits are spare.
        assert_eq!(decode(Alphabet::Standard, "Zm8=").unwrap(), b"fo");
        assert!(decode(Alphabet::Standard, "Zm9=").is_err());
    }

    #[test]
    fn a_value_beyond_the_size_limit_is_refused_before_it_is_decoded() {
        let oversized = "A".repeat(MAX_ENCODED_LEN + 4);
        let err = decode(Alphabet::Standard, &oversized).unwrap_err();
        assert!(err.contains("limit"), "{err}");
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
