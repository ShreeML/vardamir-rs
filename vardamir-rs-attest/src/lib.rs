#![no_std]

extern crate alloc;

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha3::{Digest, Sha3_256};
type HmacSha3 = Hmac<Sha3_256>;

#[derive(Default, Clone, Copy, PartialEq, Debug)] // For Testing
pub struct DeviceIdentity {
    device_id: [u8; 32],
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub struct ModelCommitment {
    fingerprint: [u8; 32],
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub struct AttestationKey {
    key: [u8; 32],
}

impl DeviceIdentity {
    pub fn new(id: [u8; 32]) -> Self {
        DeviceIdentity { device_id: id }
    }

    pub fn id(&self) -> &[u8; 32] {
        &self.device_id
    }
}

impl ModelCommitment {
    //For production:
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        ModelCommitment {
            fingerprint: hasher.finalize().into(),
        }
    }

    //For testing:
    pub fn from_string(data: &str) -> Self {
        Self::from_bytes(data.as_bytes())
    }

    pub fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }
}

impl AttestationKey {
    pub fn new(key: [u8; 32]) -> Self {
        AttestationKey { key }
    }

    pub fn derive(id: &DeviceIdentity, commitment: &ModelCommitment) -> Self {
        let device_id = id.id();
        let fingerprint = commitment.fingerprint();

        let signing_key = Hkdf::<Sha3_256>::new(Some(device_id), fingerprint);

        let mut key = [0u8; 32];
        signing_key
            .expand(&[], &mut key)
            .expect("HKDF expand failed");

        AttestationKey { key }
    }

    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }

    pub fn sign(&self, data: &[u8]) -> [u8; 32] {
        let mut hmac =
            HmacSha3::new_from_slice(&self.key).expect("Initializing hmac failed in fn sign");
        hmac.update(data);
        hmac.finalize().into_bytes().into()
    }

    pub fn verify(&self, data: &[u8], signature: &[u8; 32]) -> bool {
        let mut hmac =
            HmacSha3::new_from_slice(&self.key).expect("Initializing hmac failed in fn verify");
        hmac.update(data);
        hmac.verify_slice(signature).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_consistency() {
        let id = DeviceIdentity::new([43u8; 32]);

        let commitment1 = ModelCommitment::from_string("model_v1");
        let commitment2 = ModelCommitment::from_string("model_v1");

        let key1 = AttestationKey::derive(&id, &commitment1);
        let key2 = AttestationKey::derive(&id, &commitment2);

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_different_commitments() {
        let id = DeviceIdentity::new([43u8; 32]);

        let commitment1 = ModelCommitment::from_string("model_v1");
        let commitment2 = ModelCommitment::from_string("model_v2");

        let key1 = AttestationKey::derive(&id, &commitment1);
        let key2 = AttestationKey::derive(&id, &commitment2);

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_signature_verification() {
        let id = DeviceIdentity::new([9u8; 32]);
        let commitment = ModelCommitment::from_string("drone_nav_v3");
        let key = AttestationKey::derive(&id, &commitment);

        let data = b"Turn left";

        let signature = key.sign(data);

        let data = b"Turn right";

        assert!(!key.verify(data, &signature));
    }

    #[test]
    fn test_wrong_key() {
        let id = DeviceIdentity::new([13u8; 32]);
        let commitment = ModelCommitment::from_string("model_a");
        let key1 = AttestationKey::derive(&id, &commitment);

        let key2 = AttestationKey::derive(
            &DeviceIdentity::new([4u8; 32]),
            &ModelCommitment::from_string("model_b"),
        );

        let data = b"Test";
        let signature = key1.sign(data);
        assert!(!key2.verify(data, &signature))
    }

    #[test]
    fn test_model_commitment_fingerprint() {
        let commitment1 = ModelCommitment::from_string("bot_ver_1");
        let commitment2 = ModelCommitment::from_string("bot_ver_1");

        assert_eq!(commitment1.fingerprint(), commitment2.fingerprint())
    }
}
