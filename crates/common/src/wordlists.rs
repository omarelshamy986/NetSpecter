//! Wordlist catalog + downloader — the "which wordlist?" problem, solved once.
//!
//! Cracking WiFi is only as good as the dictionary. This module ships a curated
//! catalog of well-known, freely-downloadable lists (verified URLs), knows where
//! the OS keeps locally-installed ones, downloads a chosen list on first use,
//! and reuses it from disk forever after.
//!
//! Catalog tiers, ordered by speed-to-hit:
//!
//! - **WiFi-top** (447/4800 lines): statistically the most common WPA passphrases
//!   ever observed — cracks the lazy-password routers in seconds.
//! - **Top-10k common**: the universal "123456 / password1" tier.
//! - **rockyou**: the 14.3M-password classic; the default serious run.
//! - **Pwdb top-100k**: modern leak-db aggregate, good middle ground.
//!
//! Everything lands under `NETSPECTER_WORDLIST_DIR` (`~/.netspecter/wordlists/`)
//! and is reused on every later run — download once, use forever.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Root directory for downloaded lists (per-user, no root needed to write).
pub fn wordlist_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("NETSPECTER_WORDLIST_DIR") {
        return PathBuf::from(dir);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    PathBuf::from(home).join(".netspecter/wordlists")
}

/// One entry in the curated catalog.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WordlistEntry {
    /// Stable id used on the wire (e.g. "rockyou").
    pub id: String,
    /// Human label shown in menus (owned so custom entries can carry names).
    pub label: String,
    /// What it's good for.
    pub description: String,
    /// Approximate download size (human-readable, advisory only).
    pub size: String,
    /// Direct download URL.
    pub url: String,
    /// Suggested tier order: 0 = try first (fast small lists), higher = slower.
    pub tier: u8,
}

pub fn catalog() -> Vec<WordlistEntry> {
    vec![
    WordlistEntry {
        id: "wifi-top-447".into(),
        label: "Top-447 WiFi passwords".into(),
        description: "Statistically most common WPA passphrases; cracks lazy routers in seconds".into(),
        size: "4 KB".into(),
        url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/WiFi-WPA/probable-v2-wpa-top447.txt".into(),
        tier: 0,
    },
    WordlistEntry {
        id: "wifi-top-4800".into(),
        label: "Top-4800 WiFi passwords".into(),
        description: "Wider WPA-specific list; still runs in under a minute".into(),
        size: "45 KB".into(),
        url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt".into(),
        tier: 1,
    },
    WordlistEntry {
        id: "common-10k".into(),
        label: "Top-10k common passwords".into(),
        description: "The universal 123456/password tier from leak aggregates".into(),
        size: "80 KB".into(),
        url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/Pwdb_top-10000.txt".into(),
        tier: 2,
    },
    WordlistEntry {
        id: "pwdb-100k".into(),
        label: "Pwdb top-100k".into(),
        description: "Modern 100k leak-database aggregate; good middle ground".into(),
        size: "730 KB".into(),
        url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/Pwdb_top-100000.txt".into(),
        tier: 3,
    },
    WordlistEntry {
        id: "rockyou".into(),
        label: "rockyou (14.3M)".into(),
        description: "The classic 14M-password leak; the standard serious run (minutes+)".into(),
        size: "134 MB".into(),
        url: "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt".into(),
        tier: 4,
    },
    ]
}

/// What the CLI shows for one entry: catalog row + whether it's usable now.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WordlistStatus {
    pub entry: WordlistEntry,
    /// A usable path: downloaded cache, an OS copy, or the pending download URL.
    pub state: WordlistState,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WordlistState {
    /// Ready at this path (downloaded earlier or found on the system).
    Ready(String),
    /// Not present yet; `url` will fetch it on first use.
    Downloadable,
}

/// Where OS packages keep lists we can reuse instead of downloading.
const SYSTEM_DIRS: &[&str] = &[
    "/usr/share/wordlists",
    "/usr/share/seclists/Passwords",
    "/var/lib/wifite/wordlists",
];

/// Locate a usable copy of `id` without downloading: our cache, then system dirs.
fn find_installed(id: &str) -> Option<PathBuf> {
    let filename = match id {
        "rockyou" => "rockyou.txt",
        "wifi-top-447" => "probable-v2-wpa-top447.txt",
        "wifi-top-4800" => "probable-v2-wpa-top4800.txt",
        "common-10k" => "Pwdb_top-10000.txt",
        "pwdb-100k" => "Pwdb_top-100000.txt",
        _ => return None,
    };

    // Our download cache.
    let cached = wordlist_dir().join(filename);
    if cached.is_file() {
        return Some(cached);
    }
    // System-installed copies (kali ships rockyou at the top level).
    for dir in SYSTEM_DIRS {
        let direct = PathBuf::from(dir).join(filename);
        if direct.is_file() {
            return Some(direct);
        }
        // Kali keeps rockyou as rockyou.txt.gz too.
        let gz = PathBuf::from(dir).join(format!("{filename}.gz"));
        if gz.is_file() && id == "rockyou" {
            return Some(gz);
        }
    }
    // Kali's rockyou under its own subdir.
    if id == "rockyou" {
        let k = PathBuf::from("/usr/share/wordlists/rockyou.txt");
        if k.is_file() {
            return Some(k);
        }
    }
    None
}

/// Full menu: every catalog entry with its readiness, plus any extra .txt lists
/// the user dropped into the cache dir (their own lists appear as `custom:`).
pub fn catalog_status() -> Vec<WordlistStatus> {
    let mut out: Vec<WordlistStatus> = catalog()
        .iter()
        .map(|entry| {
            let state = match find_installed(&entry.id) {
                Some(p) => WordlistState::Ready(p.to_string_lossy().into_owned()),
                None => WordlistState::Downloadable,
            };
            WordlistStatus {
                entry: entry.clone(),
                state,
            }
        })
        .collect();

    // Custom lists the operator dropped in the cache dir.
    if let Ok(entries) = std::fs::read_dir(wordlist_dir()) {
        for e in entries.flatten() {
            let path = e.path();
            if path.extension().and_then(|x| x.to_str()) == Some("txt") {
                let name = path
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default();
                out.push(WordlistStatus {
                    entry: WordlistEntry {
                        id: "custom".into(),
                        label: name.clone(),
                        description: "your own list (from the wordlists dir)".into(),
                        size: "?".into(),
                        url: "".into(),
                        tier: 5,
                    },
                    state: WordlistState::Ready(path.to_string_lossy().into_owned()),
                });
            }
        }
    }
    out
}

/// Make a wordlist usable: return a local path, downloading on first use.
///
/// `progress` is called with the downloader's stderr lines (curl progress);
/// pass a no-op closure when running headless.
pub fn ensure_available(
    id: &str,
    mut progress: impl FnMut(&str),
) -> Result<PathBuf, String> {
    // Already usable? Done — download once, use forever.
    if let Some(p) = find_installed(id) {
        return Ok(p);
    }

    let entry = catalog()
        .into_iter()
        .find(|e| e.id == id)
        .ok_or_else(|| format!("unknown wordlist id: {id}"))?;

    let dir = wordlist_dir();
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("could not create {}: {e}", dir.display()))?;

    let filename = entry
        .url
        .rsplit('/')
        .next()
        .ok_or("bad catalog URL")?;
    let dest = dir.join(filename);
    let tmp = dir.join(format!("{filename}.part"));

    // Primary URL, then mirrors (jsdelivr CDN mirrors GitHub raw; rockyou's
    // GitHub release also lives on gitea/zzz.cm). Keeps downloads working
    // when a single host moves or rate-limits.
    let mirror = entry
        .url
        .replace("https://raw.githubusercontent.com/", "https://cdn.jsdelivr.net/gh/")
        .replace("/master/", "@master/");
    let sources = if mirror == entry.url {
        vec![entry.url.clone()]
    } else {
        vec![entry.url.clone(), mirror]
    };

    progress(&format!("downloading {} (~{})…", entry.label, entry.size));
    let mut last_err = String::new();
    for (attempt, url) in sources.iter().enumerate() {
        let status = std::process::Command::new("curl")
            .arg("-fL")
            .arg("--progress-bar")
            .arg("-o")
            .arg(&tmp)
            .arg(url)
            .status()
            .map_err(|e| format!("could not run curl: {e} (is it installed?)"))?;
        if status.success() {
            break;
        }
        let _ = std::fs::remove_file(&tmp);
        last_err = format!("download failed (curl exit {})", status.code().unwrap_or(-1));
        if attempt + 1 < sources.len() {
            progress("primary failed — trying mirror…");
        }
    }
    if !tmp.is_file() {
        return Err(format!("{last_err}. Check the internet connection."));
    }
    std::fs::rename(&tmp, &dest)
        .map_err(|e| format!("could not finalize the download: {e}"))?;
    progress(&format!("saved to {}", dest.display()));
    Ok(dest)
}

/// The sensible default chain for auto-cracking: every READY list in tier order,
/// plus rockyou last (downloading it is the operator's explicit choice).
pub fn default_chain() -> Vec<PathBuf> {
    catalog()
        .iter()
        .filter_map(|e| find_installed(&e.id))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_ids_are_unique() {
        let mut ids: Vec<_> = catalog().iter().map(|e| e.id.clone()).collect();
        ids.sort();
        let before = ids.len();
        ids.dedup();
        assert_eq!(before, ids.len());
    }

    #[test]
    fn catalog_urls_are_https() {
        for e in catalog() {
            assert!(e.url.starts_with("https://"), "{} not https", e.id);
        }
    }

    #[test]
    fn catalog_is_tier_ordered() {
        let tiers: Vec<u8> = catalog().iter().map(|e| e.tier).collect();
        let mut sorted = tiers.clone();
        sorted.sort();
        assert_eq!(tiers, sorted);
    }

    #[test]
    fn find_installed_never_panics_on_unknown() {
        assert!(find_installed("no-such-list").is_none());
    }

    #[test]
    fn ensure_available_rejects_unknown_id() {
        assert!(ensure_available("nope", |_| {}).is_err());
    }

    #[test]
    fn default_chain_never_includes_missing_lists() {
        for p in default_chain() {
            assert!(p.is_file(), "{} not a file", p.display());
        }
    }
}
