//! NetSpecter GTK4 pages.
//!
//! Each page is a self-contained GTK4 widget that the main window can embed
//! as a notebook tab. The original airgorah UI puts everything in a single
//! window with inline widgets; NetSpecter splits that into:
//!
//! - **Scan** — the original live-scan view (preserved).
//! - **Smart Wizard** — a guided flow that walks the operator through the
//!   optimal engagement sequence, with progress markers and inline rationale.
//! - **PMKID** — a dedicated tab for PMKID-only capture + verification.
//! - **Evil Twin** — the Fluxion-style rogue-AP configuration + portal picker.
//! - **Reports** — list of generated reports + open-in-browser action.
//! - **Audit Log** — read-only tail of the SHA-256-chained audit log.
//!
//! The pages communicate with the agent over the existing IPC layer; they
//! never touch the wireless interface directly.

pub mod audit_log;
pub mod autopwn;
pub mod evil_twin;
pub mod hidden_networks;
pub mod pmkid;
pub mod reports;
pub mod wizard;

pub use audit_log::AuditLogPage;
pub use autopwn::AutoPwnPage;
pub use evil_twin::EvilTwinPage;
pub use hidden_networks::HiddenNetworksPage;
pub use pmkid::PmkidPage;
pub use reports::ReportsPage;
pub use wizard::SmartWizardPage;