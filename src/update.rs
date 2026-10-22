//! Update trust model — outbound check only, fail closed.
//!
//! - The *only* update source is this project's own public GitHub
//!   repo (`auricvex/mac-audit`), configured in `Config::update_repo`.
//! - A release manifest must carry the artifact's SHA-256 and a
//!   signature. The hash is verified here. Signature verification
//!   is a scaffold stub: until Ade provides his signing key and the
//!   real verifier lands, `verify_signature` ALWAYS fails, so no
//!   update can ever install from this scaffold. That is deliberate:
//!   a stub that waved updates through would be a remote-code hole.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub version: String,
    /// Download URL — must be under the configured repo's releases.
    pub url: String,
    /// Hex SHA-256 of the artifact bytes.
    pub sha256: String,
    /// Hex signature over the artifact. Required; see module docs.
    pub signature: Option<String>,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

/// Parse `x.y.z` into a comparable tuple. Rejects anything else.
pub fn parse_version(v: &str) -> Result<(u64, u64, u64), String> {
    let v = v.trim().trim_start_matches('v');
    let parts: Vec<&str> = v.split('.').collect();
    if parts.len() != 3 {
        return Err(format!("bad version `{v}`: expected x.y.z"));
    }
    let mut n = [0u64; 3];
    for (i, p) in parts.iter().enumerate() {
        n[i] = p
            .parse()
            .map_err(|_| format!("bad version `{v}`: non-numeric part"))?;
    }
    Ok((n[0], n[1], n[2]))
}

pub fn is_newer(candidate: &str, current: &str) -> Result<bool, String> {
    Ok(parse_version(candidate)? > parse_version(current)?)
}

/// Scaffold signature stub. TODO(Ade): wire a real verifier
/// (e.g. Ed25519 over the artifact hash) with Ade's public key.
/// Until then this fails closed for every input, including
/// well-formed-looking signatures.
fn verify_signature(_manifest: &Manifest, _artifact_sha256: &str) -> Result<(), String> {
    Err(
        "signature verification not configured: no signing key installed in this scaffold build — refusing update"
            .to_string(),
    )
}

/// Verify a downloaded artifact against its manifest.
/// Checks, in order: URL belongs to the allowed repo, SHA-256
/// matches, signature present, signature valid. Any failure is an
/// error and the caller must not install.
pub fn verify_artifact(
    manifest: &Manifest,
    artifact: &[u8],
    allowed_repo: &str,
) -> Result<(), String> {
    let prefix = format!("https://github.com/{allowed_repo}/releases/");
    if !manifest.url.starts_with(&prefix) {
        return Err(format!(
            "update URL is not a release of {allowed_repo}: {}",
            manifest.url
        ));
    }
    let actual = sha256_hex(artifact);
    if !actual.eq_ignore_ascii_case(&manifest.sha256) {
        return Err(format!(
            "sha256 mismatch: manifest {}, artifact {actual}",
            manifest.sha256
        ));
    }
    match &manifest.signature {
        None => return Err("manifest has no signature — refusing update".to_string()),
        Some(s) if s.trim().is_empty() => {
            return Err("manifest signature is empty — refusing update".to_string());
        }
        Some(_) => {}
    }
    verify_signature(manifest, &actual)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_for(bytes: &[u8], signature: Option<String>) -> Manifest {
        Manifest {
            version: "0.2.0".to_string(),
            url: "https://github.com/auricvex/mac-audit/releases/download/v0.2.0/mac-audit.tar.gz"
                .to_string(),
            sha256: sha256_hex(bytes),
            signature,
        }
    }

    #[test]
    fn version_compare_semver() {
        assert!(is_newer("0.2.0", "0.1.0").unwrap());
        assert!(is_newer("v1.0.0", "0.9.9").unwrap());
        assert!(!is_newer("0.1.0", "0.1.0").unwrap());
        assert!(!is_newer("0.1.0", "0.2.0").unwrap());
        assert!(parse_version("1.2").is_err());
        assert!(parse_version("a.b.c").is_err());
    }

    #[test]
    fn rejects_bad_hash() {
        let mut m = manifest_for(b"real artifact", Some("deadbeef".into()));
        m.sha256 = sha256_hex(b"different bytes");
        let err = verify_artifact(&m, b"real artifact", "auricvex/mac-audit").unwrap_err();
        assert!(err.contains("sha256 mismatch"), "{err}");
    }

    #[test]
    fn rejects_missing_signature() {
        let m = manifest_for(b"artifact", None);
        let err = verify_artifact(&m, b"artifact", "auricvex/mac-audit").unwrap_err();
        assert!(err.contains("no signature"), "{err}");
    }

    #[test]
    fn rejects_foreign_repo_url() {
        let mut m = manifest_for(b"artifact", Some("deadbeef".into()));
        m.url = "https://example.com/mac-audit.tar.gz".to_string();
        let err = verify_artifact(&m, b"artifact", "auricvex/mac-audit").unwrap_err();
        assert!(err.contains("not a release"), "{err}");
    }

    #[test]
    fn correct_hash_still_refused_without_configured_signing_key() {
        // Fail-closed scaffold: even a perfect hash + a present
        // signature cannot install until Ade's verifier/key lands.
        let m = manifest_for(b"artifact", Some("deadbeef".into()));
        let err = verify_artifact(&m, b"artifact", "auricvex/mac-audit").unwrap_err();
        assert!(
            err.contains("signature verification not configured"),
            "{err}"
        );
    }
}
