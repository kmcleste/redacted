use once_cell::sync::Lazy;
use regex::Regex;

use crate::entities::{DetectedSpan, EntityType};

use super::Detector;

static AWS_ACCESS_KEY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}").unwrap());

static AWS_SECRET_CTX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|aws_secret)\s*[=:]\s*([A-Za-z0-9+/]{40})")
        .unwrap()
});

static GITHUB_TOKEN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{82}").unwrap()
});

static PEM_BLOCK: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"-----BEGIN [A-Z ]{1,40}-----").unwrap());

static CONNECTION_STRING: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis(?:s)?|amqps?|smtps?|mssql)://[^\s"']{6,}"#,
    )
    .unwrap()
});

static GENERIC_SECRET: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?:api[_\-]?key|api[_\-]?token|access[_\-]?token|secret[_\-]?key|auth[_\-]?token)\s*[=:"']\s*([A-Za-z0-9+/=_\-]{16,})"#,
    )
    .unwrap()
});

pub struct SecretDetector;

impl Detector for SecretDetector {
    fn name(&self) -> &'static str {
        "SecretDetector"
    }

    fn detect(&self, text: &str) -> Vec<DetectedSpan> {
        let mut spans = Vec::new();

        for m in AWS_ACCESS_KEY.find_iter(text) {
            spans.push(DetectedSpan::new(m.start(), m.end(), EntityType::AwsKey, m.as_str(), 0.99));
        }

        // Named capture group 1 for the actual secret value.
        for cap in AWS_SECRET_CTX.captures_iter(text) {
            let m = cap.get(1).unwrap();
            spans.push(DetectedSpan::new(m.start(), m.end(), EntityType::AwsKey, m.as_str(), 0.99));
        }

        for m in GITHUB_TOKEN.find_iter(text) {
            spans.push(DetectedSpan::new(m.start(), m.end(), EntityType::GithubToken, m.as_str(), 0.99));
        }

        for m in PEM_BLOCK.find_iter(text) {
            spans.push(DetectedSpan::new(m.start(), m.end(), EntityType::PemBlock, m.as_str(), 0.99));
        }

        for m in CONNECTION_STRING.find_iter(text) {
            spans.push(DetectedSpan::new(m.start(), m.end(), EntityType::ConnectionString, m.as_str(), 0.95));
        }

        for cap in GENERIC_SECRET.captures_iter(text) {
            let m = cap.get(1).unwrap();
            spans.push(DetectedSpan::new(m.start(), m.end(), EntityType::GenericSecret, m.as_str(), 0.90));
        }

        spans.sort_by_key(|s| s.start);
        spans
    }
}
