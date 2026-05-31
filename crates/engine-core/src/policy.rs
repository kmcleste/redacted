use std::collections::HashMap;

use crate::{entities::EntityType, modality::Modality};

// ---------------------------------------------------------------------------
// Decision
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Mask,
    Skip,
    FailClosed,
}

// ---------------------------------------------------------------------------
// Per-entity policy
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct EntityPolicy {
    pub enabled: bool,
    pub threshold: f32,
    pub fail_closed: bool,
}

impl EntityPolicy {
    pub fn decide(&self, score: f32) -> Decision {
        if !self.enabled {
            return Decision::Skip;
        }
        if score >= self.threshold {
            Decision::Mask
        } else {
            Decision::Skip
        }
    }
}

// ---------------------------------------------------------------------------
// Default thresholds (D6: fail-closed baseline)
// ---------------------------------------------------------------------------

fn default_threshold(et: EntityType) -> f32 {
    match et {
        EntityType::Ssn => 0.85,
        EntityType::CreditCard => 0.80,
        EntityType::BankRouting => 0.75,
        EntityType::BankAccount => 0.70,
        EntityType::Npi => 0.80,
        EntityType::DateOfBirth => 0.75,
        EntityType::MedicalRecord => 0.70,
        EntityType::AwsKey => 0.99,
        EntityType::GithubToken => 0.99,
        EntityType::PemBlock => 0.99,
        EntityType::ConnectionString => 0.95,
        EntityType::GenericSecret => 0.90,
        EntityType::Person => 0.70,
        EntityType::Org => 0.60,
        EntityType::Address => 0.65,
        _ => 0.50,
    }
}

// ---------------------------------------------------------------------------
// PolicyBundle
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PolicyBundle {
    pub version: String,
    pub default_fail_closed: bool,
    pub modality: Modality,
    pub entity_policies: HashMap<EntityType, EntityPolicy>,
}

impl Default for PolicyBundle {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyBundle {
    pub fn new() -> Self {
        let mut bundle = Self {
            version: "0.1.0".into(),
            default_fail_closed: true,
            modality: Modality::Prose,
            entity_policies: HashMap::new(),
        };
        // Populate with defaults for every known entity type.
        let all = [
            EntityType::Ssn, EntityType::CreditCard, EntityType::BankRouting,
            EntityType::BankAccount, EntityType::Email, EntityType::Phone,
            EntityType::IpAddress, EntityType::Vin, EntityType::PolicyNumber,
            EntityType::ClaimId, EntityType::MemberId, EntityType::GroupId,
            EntityType::Npi, EntityType::DateOfBirth, EntityType::MedicalRecord,
            EntityType::AwsKey, EntityType::GithubToken, EntityType::PemBlock,
            EntityType::ConnectionString, EntityType::GenericSecret,
            EntityType::Person, EntityType::Address, EntityType::Org,
        ];
        for et in all {
            bundle.entity_policies.insert(
                et,
                EntityPolicy {
                    enabled: true,
                    threshold: default_threshold(et),
                    fail_closed: true,
                },
            );
        }
        bundle
    }

    /// Relaxed policy for confirmed code-channel traffic (D9).
    /// Secrets stay at max; fuzzy NER is suppressed.
    pub fn for_code_traffic() -> Self {
        let mut bundle = Self::new();
        bundle.modality = Modality::Code;
        for et in [EntityType::Person, EntityType::Org, EntityType::Address] {
            bundle.entity_policies.insert(
                et,
                EntityPolicy { enabled: false, threshold: 1.0, fail_closed: false },
            );
        }
        bundle
    }

    pub fn decide(&self, entity_type: EntityType, score: f32) -> Decision {
        match self.entity_policies.get(&entity_type) {
            Some(p) => p.decide(score),
            None => {
                if self.default_fail_closed {
                    Decision::Mask
                } else {
                    Decision::Skip
                }
            }
        }
    }

    pub fn is_enabled(&self, entity_type: EntityType) -> bool {
        self.entity_policies.get(&entity_type).map_or(true, |p| p.enabled)
    }
}
