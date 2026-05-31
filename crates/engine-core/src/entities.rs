use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// EntityType
// ---------------------------------------------------------------------------

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EntityType {
    // Structured PII
    Ssn,
    CreditCard,
    BankRouting,
    BankAccount,
    Email,
    Phone,
    IpAddress,
    Vin,

    // Domain / insurance identifiers
    PolicyNumber,
    ClaimId,
    MemberId,
    GroupId,
    Npi,

    // PHI (HIPAA)
    DateOfBirth,
    MedicalRecord,

    // Secrets (always high-priority; never suppressed by code-traffic policy)
    AwsKey,
    GithubToken,
    PemBlock,
    ConnectionString,
    GenericSecret,

    // NER-lane stubs (soft real-time; not populated by deterministic detectors)
    Person,
    Address,
    Org,
}

impl EntityType {
    /// The canonical string used in placeholder tokens: `[SSN_1]`, `[CREDIT_CARD_2]`, etc.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ssn => "SSN",
            Self::CreditCard => "CREDIT_CARD",
            Self::BankRouting => "BANK_ROUTING",
            Self::BankAccount => "BANK_ACCOUNT",
            Self::Email => "EMAIL",
            Self::Phone => "PHONE",
            Self::IpAddress => "IP_ADDRESS",
            Self::Vin => "VIN",
            Self::PolicyNumber => "POLICY_NUMBER",
            Self::ClaimId => "CLAIM_ID",
            Self::MemberId => "MEMBER_ID",
            Self::GroupId => "GROUP_ID",
            Self::Npi => "NPI",
            Self::DateOfBirth => "DATE_OF_BIRTH",
            Self::MedicalRecord => "MEDICAL_RECORD",
            Self::AwsKey => "AWS_KEY",
            Self::GithubToken => "GITHUB_TOKEN",
            Self::PemBlock => "PEM_BLOCK",
            Self::ConnectionString => "CONNECTION_STRING",
            Self::GenericSecret => "GENERIC_SECRET",
            Self::Person => "PERSON",
            Self::Address => "ADDRESS",
            Self::Org => "ORG",
        }
    }

    pub fn is_secret(self) -> bool {
        matches!(
            self,
            Self::AwsKey
                | Self::GithubToken
                | Self::PemBlock
                | Self::ConnectionString
                | Self::GenericSecret
        )
    }

    pub fn is_phi(self) -> bool {
        matches!(
            self,
            Self::DateOfBirth | Self::MedicalRecord | Self::Npi | Self::MemberId
        )
    }
}

impl fmt::Display for EntityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// DetectedSpan
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct DetectedSpan {
    pub start: usize,
    pub end: usize,
    pub entity_type: EntityType,
    /// Substring of the original text — owned so callers don't need to hold a text ref.
    pub original_value: String,
    /// Confidence score in [0, 1].
    pub score: f32,
}

impl DetectedSpan {
    pub fn new(
        start: usize,
        end: usize,
        entity_type: EntityType,
        original_value: impl Into<String>,
        score: f32,
    ) -> Self {
        Self {
            start,
            end,
            entity_type,
            original_value: original_value.into(),
            score,
        }
    }

    pub fn len(&self) -> usize {
        self.end - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    pub fn overlaps(&self, other: &DetectedSpan) -> bool {
        self.start < other.end && other.start < self.end
    }
}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct MaskResult {
    pub text: String,
    pub correlation_id: String,
    pub entity_counts: HashMap<EntityType, usize>,
}

impl MaskResult {
    pub fn was_masked(&self) -> bool {
        !self.entity_counts.is_empty()
    }
}

#[derive(Debug)]
pub struct RehydrateResult {
    pub text: String,
    pub correlation_id: String,
    pub rehydrated_count: usize,
}
