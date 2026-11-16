//! Prometheus text exposition: a few counters each process keeps, and the figures every scrape reads from the database
//! (accounts, pages, reports, screening, storage). No client library; the internal port serves it.

use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};

use link_in_bio_store::Stats;

#[derive(Debug, Default)]
pub struct Metrics {
    pub signups: AtomicU64,
    pub signins: AtomicU64,
    pub signin_failures: AtomicU64,
    pub publishes: AtomicU64,
    pub reports: AtomicU64,
    pub checkouts: AtomicU64,
    pub payments: AtomicU64,
    pub notification_failures: AtomicU64,
    pub screenings: AtomicU64,
    pub pages_served: AtomicU64,
    pub job_failures: AtomicU64,
}

impl Metrics {
    pub fn inc(c: &AtomicU64) {
        c.fetch_add(1, Ordering::Relaxed);
    }

    pub fn render(&self, stats: Option<&Stats>, web_risk_calls: Option<(i64, i64)>) -> String {
        let mut s = String::new();
        for (name, help, c) in [
            ("link_in_bio_signups_total", "Accounts created", &self.signups),
            ("link_in_bio_signins_total", "Successful sign-ins", &self.signins),
            ("link_in_bio_signin_failures_total", "Refused sign-in attempts", &self.signin_failures),
            ("link_in_bio_publishes_total", "Pages published", &self.publishes),
            ("link_in_bio_reports_total", "Reports received", &self.reports),
            ("link_in_bio_checkouts_total", "Checkouts started", &self.checkouts),
            ("link_in_bio_payments_total", "Payments applied to a paid period", &self.payments),
            ("link_in_bio_notification_failures_total", "Provider notifications refused", &self.notification_failures),
            ("link_in_bio_screenings_total", "Links screened", &self.screenings),
            ("link_in_bio_pages_served_total", "Tenant page documents served", &self.pages_served),
            ("link_in_bio_job_failures_total", "Worker duties that failed", &self.job_failures),
        ] {
            let _ = writeln!(s, "# HELP {name} {help}\n# TYPE {name} counter\n{name} {}", c.load(Ordering::Relaxed));
        }
        if let Some(st) = stats {
            for (name, help, v) in [
                ("link_in_bio_accounts_active", "Active accounts", st.accounts_active),
                ("link_in_bio_accounts_suspended", "Suspended accounts", st.accounts_suspended),
                ("link_in_bio_accounts_free", "Active free (invited) accounts", st.accounts_free),
                ("link_in_bio_accounts_paid", "Accounts paid up now", st.accounts_paid),
                ("link_in_bio_pages_published", "Published pages", st.pages_published),
                ("link_in_bio_reports_open", "Open reports", st.reports_open),
                ("link_in_bio_reports_open_over_24h", "Reports open for more than 24 hours", st.reports_open_over_24h),
                ("link_in_bio_appeals_open", "Open appeals", st.appeals_open),
                ("link_in_bio_links_flagged", "Links hidden by screening", st.links_flagged),
                (
                    "link_in_bio_links_unknown",
                    "Links not screened yet (checked again within the hour)",
                    st.links_unknown,
                ),
                ("link_in_bio_storage_bytes", "Bytes of pages, versions and pictures", st.storage_bytes),
                ("link_in_bio_checkouts_open", "Checkouts not yet paid or expired", st.checkouts_open),
            ] {
                let _ = writeln!(s, "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {v}");
            }
        }
        if let Some((used, cap)) = web_risk_calls {
            let _ = writeln!(
                s,
                "# HELP link_in_bio_web_risk_calls Web Risk calls this month\n# TYPE link_in_bio_web_risk_calls gauge\n\
                 link_in_bio_web_risk_calls {used}\n# HELP link_in_bio_web_risk_cap The monthly hard cap\n\
                 # TYPE link_in_bio_web_risk_cap gauge\nlink_in_bio_web_risk_cap {cap}"
            );
        }
        s
    }
}
