//! The Analyze tab's results: one row per item (from the run's statistics.json and technical.json) and, for the
//! selected item, its chain trees (from chain.json: one [`ChainVerdict`] per end-entity certificate), the parsed
//! fields of the selected node and the item's certificate.txt. Read-only: nothing here writes.

use rv_certcheck_core::certs::{
    CertInfo, ChainNode, ChainStatus, ChainVerdict, NodeStatus, RevocationStatus,
};
use serde_json::Value;
use std::path::{Path, PathBuf};

/// One row of the results table.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ResultRow {
    pub index: u64,
    pub path: String,
    pub name: String,
    /// What the item is (`certificate`, `crl`, `timestamp_token`, ... or the inventory type).
    pub kind: String,
    /// ok | attention | problem
    pub status: String,
    pub findings: Vec<String>,
    /// `<report>/items/<NNNNN-name>`
    pub folder: PathBuf,
}

/// The badge drawn on a chain node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Badge {
    /// OpenSSL accepted this depth.
    Ok,
    /// OpenSSL reported an error at this depth.
    Error,
    /// The path could not be built further (missing issuer).
    Incomplete,
}

impl Badge {
    /// i18n `ui` key of the badge text.
    pub fn key(&self) -> &'static str {
        match self {
            Badge::Ok => "badge_ok",
            Badge::Error => "badge_error",
            Badge::Incomplete => "badge_incomplete",
        }
    }
}

/// One node of a chain tree, depth 0 (the leaf) first.
#[derive(Clone, Debug, PartialEq)]
pub struct TreeNode {
    pub depth: u32,
    pub subject: String,
    pub issuer: String,
    pub badge: Badge,
    pub openssl_code: i32,
    /// OpenSSL's reason (`ok` when the code is 0).
    pub reason: String,
    /// The `--anchor` this node was trusted from.
    pub anchor: Option<String>,
    /// `good (file:…crl)`, `revoked keyCompromise at …`, `unknown: …`; None when not checked.
    pub revocation: Option<String>,
    pub trust_list: Option<String>,
    pub cert: CertInfo,
}

/// A chain from the leaf to its anchor (or as far as it could be built).
#[derive(Clone, Debug, PartialEq)]
pub struct ChainTree {
    pub status: ChainStatus,
    /// i18n `ui` key of the overall status.
    pub status_key: &'static str,
    pub at: String,
    pub at_source: String,
    pub purpose: String,
    pub openssl_code: i32,
    pub openssl_reason: String,
    pub nodes: Vec<TreeNode>,
    /// Every error OpenSSL reported, `depth N: code (reason)`.
    pub errors: Vec<String>,
    pub notes: Vec<String>,
    /// True when the last node is a trust anchor.
    pub reaches_anchor: bool,
}

pub fn revocation_text(r: &RevocationStatus) -> String {
    match r {
        RevocationStatus::Good { source } => format!("good ({})", source.origin),
        RevocationStatus::Revoked {
            reason,
            revoked_at,
            source,
        } => format!("revoked {reason} at {revoked_at} ({})", source.origin),
        RevocationStatus::Unknown { source } => format!("unknown: {source}"),
    }
}

fn node(n: &ChainNode) -> TreeNode {
    let badge = match n.status {
        NodeStatus::Ok => Badge::Ok,
        NodeStatus::Error => Badge::Error,
        NodeStatus::Incomplete => Badge::Incomplete,
    };
    let reason = if n.openssl_code == 0 && n.openssl_reason.is_empty() {
        "ok".to_string()
    } else {
        n.openssl_reason.clone()
    };
    let revocation = n.revocation.as_ref().map(|r| {
        let t = revocation_text(r);
        match &n.revocation_note {
            Some(note) => format!("{t}; {note}"),
            None => t,
        }
    });
    TreeNode {
        depth: n.depth,
        subject: n.cert.subject.clone(),
        issuer: n.cert.issuer.clone(),
        badge,
        openssl_code: n.openssl_code,
        reason,
        anchor: n.anchor.clone(),
        revocation,
        trust_list: n.trust_list.as_ref().map(|t| {
            format!(
                "{} {}: {} / {} ({})",
                t.list, t.snapshot_id, t.tsp_name, t.service_name, t.status_at
            )
        }),
        cert: n.cert.clone(),
    }
}

/// Builds the tree of one verdict: nodes sorted leaf (depth 0) to anchor.
pub fn chain_tree(v: &ChainVerdict) -> ChainTree {
    let mut nodes: Vec<TreeNode> = v.nodes.iter().map(node).collect();
    nodes.sort_by_key(|n| n.depth);
    let status_key = match v.status {
        ChainStatus::Valid => "chain_valid",
        ChainStatus::Untrusted => "chain_untrusted",
        ChainStatus::Invalid => "chain_invalid",
    };
    ChainTree {
        status: v.status,
        status_key,
        at: v.at.clone(),
        at_source: v.at_source.clone(),
        purpose: v.purpose.name().to_string(),
        openssl_code: v.openssl_code,
        openssl_reason: v.openssl_reason.clone(),
        reaches_anchor: nodes.last().is_some_and(|n| n.anchor.is_some()),
        nodes,
        errors: v
            .errors
            .iter()
            .map(|e| format!("depth {}: {} ({})", e.depth, e.code, e.reason))
            .collect(),
        notes: v.notes.clone(),
    }
}

/// The parsed fields of a certificate shown next to the tree: (i18n `ui` key, value). Empty values are left out.
pub fn cert_fields(c: &CertInfo) -> Vec<(&'static str, String)> {
    let key = format!(
        "{} {}{}",
        c.key.algorithm,
        c.key.bits.map(|b| b.to_string()).unwrap_or_default(),
        c.key
            .curve
            .as_deref()
            .map(|x| format!(" {x}"))
            .unwrap_or_default()
    );
    let bc = c.basic_constraints.as_ref().map(|b| {
        format!(
            "CA:{}{}{}",
            if b.ca { "TRUE" } else { "FALSE" },
            b.path_len
                .map(|p| format!(", pathlen:{p}"))
                .unwrap_or_default(),
            if b.critical { " (critical)" } else { "" }
        )
    });
    let list = |v: &[String], critical: bool| {
        if v.is_empty() {
            String::new()
        } else {
            format!(
                "{}{}",
                v.join(", "),
                if critical { " (critical)" } else { "" }
            )
        }
    };
    let rows = vec![
        ("f_subject", c.subject.clone()),
        ("f_issuer", c.issuer.clone()),
        ("f_serial", c.serial_hex.clone()),
        ("f_not_before", c.not_before.clone()),
        ("f_not_after", c.not_after.clone()),
        ("f_key", key.trim().to_string()),
        ("f_signature", c.signature_algorithm.clone()),
        (
            "f_sans",
            c.sans
                .iter()
                .map(|g| format!("{}:{}", g.kind, g.value))
                .collect::<Vec<_>>()
                .join(", "),
        ),
        ("f_key_usage", list(&c.key_usage, c.key_usage_critical)),
        ("f_eku", list(&c.eku, c.eku_critical)),
        ("f_basic_constraints", bc.unwrap_or_default()),
        ("f_policies", c.policy_oids.join(", ")),
        ("f_crl_dps", c.crl_dps.join(", ")),
        ("f_ocsp", c.aia_ocsp.join(", ")),
        ("f_ski", c.ski_hex.clone().unwrap_or_default()),
        ("f_aki", c.aki_hex.clone().unwrap_or_default()),
        ("f_sha256", c.sha256.clone()),
        ("f_sha1", c.sha1.clone()),
    ];
    rows.into_iter().filter(|(_, v)| !v.is_empty()).collect()
}

/// The rows of a finished run, from `<report>/statistics.json` (final findings, after the cross-item stage) and
/// each item's technical.json (its kind).
pub fn load_rows(report_dir: &Path) -> Result<Vec<ResultRow>, String> {
    let p = report_dir.join("statistics.json");
    let stats: Value = serde_json::from_slice(
        &std::fs::read(&p).map_err(|e| format!("cannot read {}: {e}", p.display()))?,
    )
    .map_err(|e| format!("{}: {e}", p.display()))?;
    let mut rows = vec![];
    for it in stats["items"].as_array().cloned().unwrap_or_default() {
        let folder = report_dir.join(it["report_folder"].as_str().unwrap_or_default());
        let tech: Value = std::fs::read(folder.join("technical.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or(Value::Null);
        let kind = tech["certificates"]["kind"]
            .as_str()
            .or(tech["item"]["detected_type"].as_str())
            .unwrap_or("unknown")
            .to_string();
        let path = it["path"].as_str().unwrap_or_default().to_string();
        rows.push(ResultRow {
            index: it["index"].as_u64().unwrap_or_default(),
            name: Path::new(&path)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.clone()),
            path,
            kind,
            status: it["status"].as_str().unwrap_or_default().to_string(),
            findings: it["findings"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
            folder,
        });
    }
    Ok(rows)
}

/// What the chain view shows for one item.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ItemView {
    pub row: usize,
    pub trees: Vec<ChainTree>,
    /// (tree, node) of the node whose fields are shown.
    pub selected: Option<(usize, usize)>,
    /// certificate.txt (OpenSSL text dump), empty when the item has none.
    pub certificate_text: String,
    /// Failed analysis steps recorded in chain.json.
    pub errors: Vec<String>,
}

/// Loads chain.json and certificate.txt of one item (a non-certificate item has no chain.json: empty view).
pub fn load_item(row: usize, r: &ResultRow) -> ItemView {
    let chain: Value = std::fs::read(r.folder.join("chain.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(Value::Null);
    let mut verdicts: Vec<ChainVerdict> = chain["verdicts"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| serde_json::from_value(v.clone()).ok())
                .collect()
        })
        .unwrap_or_default();
    if let Some(ts) = chain
        .pointer("/timestamp/signer_chain")
        .filter(|v| !v.is_null())
        .and_then(|v| serde_json::from_value::<ChainVerdict>(v.clone()).ok())
    {
        verdicts.push(ts);
    }
    let trees: Vec<ChainTree> = verdicts.iter().map(chain_tree).collect();
    ItemView {
        row,
        selected: (!trees.is_empty() && !trees[0].nodes.is_empty()).then_some((0, 0)),
        trees,
        certificate_text: std::fs::read_to_string(r.folder.join("certificate.txt"))
            .unwrap_or_default(),
        errors: chain["errors"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|e| {
                        format!(
                            "{}: {}",
                            e["operation"].as_str().unwrap_or(""),
                            e["error"].as_str().unwrap_or("")
                        )
                    })
                    .collect()
            })
            .unwrap_or_default(),
    }
}

impl ItemView {
    pub fn selected_node(&self) -> Option<&TreeNode> {
        let (t, n) = self.selected?;
        self.trees.get(t)?.nodes.get(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rv_certcheck_core::certs::{ChainError, RevocationSource};

    fn cert(subject: &str, issuer: &str) -> CertInfo {
        CertInfo {
            subject: subject.into(),
            issuer: issuer.into(),
            ..Default::default()
        }
    }

    #[test]
    fn chain_tree_goes_from_leaf_to_anchor_with_badges_and_reasons() {
        let v = ChainVerdict {
            status: ChainStatus::Invalid,
            at: "2026-06-01T00:00:00Z".into(),
            at_source: "given".into(),
            openssl_code: 23,
            openssl_reason: "certificate revoked".into(),
            // Deliberately out of order: the tree sorts by depth.
            nodes: vec![
                ChainNode {
                    depth: 2,
                    cert: cert("CN=Root", "CN=Root"),
                    anchor: Some("file:root.crt".into()),
                    ..Default::default()
                },
                ChainNode {
                    depth: 0,
                    cert: cert("CN=leaf", "CN=Int"),
                    status: NodeStatus::Error,
                    openssl_code: 23,
                    openssl_reason: "certificate revoked".into(),
                    revocation: Some(RevocationStatus::Revoked {
                        reason: "keyCompromise".into(),
                        revoked_at: "2026-02-01T00:00:00Z".into(),
                        source: RevocationSource {
                            origin: "item:4".into(),
                            ..Default::default()
                        },
                    }),
                    ..Default::default()
                },
                ChainNode {
                    depth: 1,
                    cert: cert("CN=Int", "CN=Root"),
                    revocation: Some(RevocationStatus::Unknown {
                        source: "no CRL or OCSP response supplied".into(),
                    }),
                    ..Default::default()
                },
            ],
            errors: vec![ChainError {
                depth: 0,
                code: 23,
                reason: "certificate revoked".into(),
            }],
            ..Default::default()
        };
        let t = chain_tree(&v);
        let subjects: Vec<&str> = t.nodes.iter().map(|n| n.subject.as_str()).collect();
        assert_eq!(subjects, ["CN=leaf", "CN=Int", "CN=Root"]);
        assert_eq!(t.nodes[0].badge, Badge::Error);
        assert_eq!(t.nodes[0].reason, "certificate revoked");
        assert!(
            t.nodes[0]
                .revocation
                .as_deref()
                .unwrap()
                .starts_with("revoked keyCompromise at 2026-02-01")
        );
        assert_eq!(t.nodes[1].badge, Badge::Ok);
        assert_eq!(t.nodes[1].reason, "ok");
        assert!(
            t.nodes[1]
                .revocation
                .as_deref()
                .unwrap()
                .starts_with("unknown")
        );
        assert_eq!(t.nodes[2].anchor.as_deref(), Some("file:root.crt"));
        assert!(t.reaches_anchor);
        assert_eq!(t.status_key, "chain_invalid");
        assert_eq!(t.errors, ["depth 0: 23 (certificate revoked)"]);

        let untrusted = ChainVerdict {
            status: ChainStatus::Untrusted,
            nodes: vec![ChainNode {
                depth: 0,
                cert: cert("CN=x", "CN=gone"),
                status: NodeStatus::Incomplete,
                openssl_code: 20,
                openssl_reason: "unable to get local issuer certificate".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let t = chain_tree(&untrusted);
        assert_eq!(t.nodes[0].badge, Badge::Incomplete);
        assert!(!t.reaches_anchor);
        assert_eq!(t.status_key, "chain_untrusted");
    }

    #[test]
    fn fields_leave_out_empty_values() {
        let mut c = cert("CN=a", "CN=b");
        c.eku = vec!["serverAuth".into()];
        c.eku_critical = true;
        let f = cert_fields(&c);
        assert!(f.contains(&("f_eku", "serverAuth (critical)".into())));
        assert!(!f.iter().any(|(k, _)| *k == "f_sans"));
    }
}
