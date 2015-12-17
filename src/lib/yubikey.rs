use ykpers_rs::{YubikeyDevice, ChallengeResponse, ChallengeResponseParams, SHA1_RESPONSE_LENGTH, SHA1_BLOCK_LENGTH};
use uuid::Uuid;

use model::{YubikeySlot, YubikeyEntryType};
use context::{MainContext, YubikeyInput, Error, Result, PasswordInput};
use io::KeyWrapper;
use io::yubikey;

impl YubikeyInput for MainContext {
    fn read_yubikey(&self, name: Option<&str>, uuid: &Uuid, slot: YubikeySlot, entry_type: YubikeyEntryType) -> Result<KeyWrapper> {
        let mut dev = try!(acquire_device());
        let challenge = try!(self.read_password(&challenge_prompt(name)));
        match entry_type {
            YubikeyEntryType::ChallengeResponse => read_challenge_response(&mut dev, slot, challenge.as_slice()).map(|k| yubikey::wrap(&k)),
            YubikeyEntryType::HybridChallengeResponse => {
                let other_passphrase = try!(self.read_password("Please enter the other passphrase: "));
                read_hybrid_challenge_response(&mut dev, slot, challenge, other_passphrase, uuid)
            }
        }
    }
}

fn challenge_prompt(maybe_name: Option<&str>) -> String {
    if let Some(name) = maybe_name {
        format!("Please enter challenge passphrase for {}: ", name)
    } else {
        format!("Please enter new challenge passphrase: ")
    }
}

fn acquire_device() -> Result<YubikeyDevice> {
    YubikeyDevice::new().map_err(|err| Error::YubikeyError { message: format!("Failed to get Yubikey device: {:?}", err) })
}

fn read_challenge_response(dev: &mut YubikeyDevice, slot: YubikeySlot, challenge: &[u8]) -> Result<[u8; SHA1_RESPONSE_LENGTH]> {
    let params = ChallengeResponseParams {
        slot: slot,
        is_hmac: true,
    };
    println!("Please interact with the Yubikey now...");
    let mut response = [0u8; SHA1_BLOCK_LENGTH];
    dev.challenge_response(params, &challenge, &mut response)
       .map(|_| {
           // FIXME: wait until copy_memory or similar is stable
           let mut fix_response = [0u8; SHA1_RESPONSE_LENGTH];
           {
               for (i, b) in response.iter().take(SHA1_RESPONSE_LENGTH).enumerate() {
                   fix_response[i] = *b;
               }
           }
           fix_response
       })
       .map_err(|err| Error::YubikeyError { message: format!("Failed Yubikey challenge-response: {:?}", err) })
}

#[cfg(not(feature = "yubikey_hybrid"))]
fn read_hybrid_challenge_response(dev: &mut YubikeyDevice,
                                  slot: YubikeySlot,
                                  challenge: KeyWrapper,
                                  other_passphrase: KeyWrapper,
                                  uuid: &Uuid)
                                  -> Result<KeyWrapper> {
    Err(Error::FeatureNotAvailable)
}

#[cfg(feature = "yubikey_hybrid")]
mod hybrid {
    use ykpers_rs::{YubikeyDevice, SHA1_RESPONSE_LENGTH, SHA1_BLOCK_LENGTH};
    use sodiumoxide;
    use sodiumoxide::crypto::auth::hmacsha512;
    use sodiumoxide::crypto::hash::sha256;
    use sodiumoxide::crypto::pwhash::scryptsalsa208sha256;
    use uuid::Uuid;

    use model::YubikeySlot;
    use context::{Error, Result};
    use io::KeyWrapper;
    use io::yubikey;
    use super::read_challenge_response;

    // taken from crypto_pwhash_scrypt208sha256
    const PWHASH_OPSLIMIT: usize = 33554432;
    const PWHASH_MEMLIMIT: usize = 1073741824;

    fn salt_from_uuid(uuid: &Uuid) -> scryptsalsa208sha256::Salt {
        let sha256::Digest(bytes) = sha256::hash(uuid.as_bytes());
        scryptsalsa208sha256::Salt(bytes)
    }

    fn derive_challenge_key(challenge: &[u8], uuid: &Uuid) -> Result<[u8; SHA1_BLOCK_LENGTH]> {
        let mut derived_key = [0u8; SHA1_BLOCK_LENGTH];
        let salt = salt_from_uuid(uuid);
        try!{
            scryptsalsa208sha256::derive_key(&mut derived_key,
                                             challenge,
                                             &salt,
                                             scryptsalsa208sha256::OpsLimit(PWHASH_OPSLIMIT),
                                             scryptsalsa208sha256::MemLimit(PWHASH_MEMLIMIT))
                .map_err(|_| Error::UnknownCryptoError)
                .map(|_| ())
        }
        Ok(derived_key)
    }

    fn hash_challenge_and_then_response(dev: &mut YubikeyDevice,
                                        slot: YubikeySlot,
                                        challenge: &[u8],
                                        uuid: &Uuid)
                                        -> Result<[u8; SHA1_RESPONSE_LENGTH]> {
        let derived_key = try!(derive_challenge_key(challenge, uuid));
        read_challenge_response(dev, slot, &derived_key)
    }

    pub fn read_hybrid_challenge_response(dev: &mut YubikeyDevice,
                                          slot: YubikeySlot,
                                          challenge: KeyWrapper,
                                          other_passphrase: KeyWrapper,
                                          uuid: &Uuid)
                                          -> Result<KeyWrapper> {
        // TODO: explain in more detail the reasoning behind home-brewed crypto...
        sodiumoxide::init();

        let response = try!(hash_challenge_and_then_response(dev, slot, challenge.as_slice(), uuid));
        let sha256::Digest(response_hash) = sha256::hash(&response);
        let auth_key = hmacsha512::Key(response_hash);
        let hmacsha512::Tag(final_key) = hmacsha512::authenticate(other_passphrase.as_slice(), &auth_key);
        Ok(yubikey::wrap(&final_key))
    }
}

#[cfg(feature = "yubikey_hybrid")]
use yubikey::hybrid::read_hybrid_challenge_response;
