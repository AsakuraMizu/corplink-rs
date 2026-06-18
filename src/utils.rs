use std::io::{self, BufRead};

use aes::Aes256;
use anyhow::{anyhow, Context, Result};
use base32::Alphabet;
use base64::engine::general_purpose::STANDARD as base64;
use base64::Engine;
use cbc::cipher::{block_padding::Pkcs7, generic_array::GenericArray, BlockEncryptMut, KeyIvInit};
use rand::rngs::OsRng;
use sha1::{Digest, Sha1};
use x25519_dalek::{PublicKey, StaticSecret};

pub async fn read_line() -> Result<String> {
    io::stdin()
        .lock()
        .lines()
        .next()
        .context("stdin closed")?
        .context("failed to read line")
}

pub fn b32_decode(s: &str) -> Result<Vec<u8>> {
    base32::decode(Alphabet::RFC4648 { padding: true }, s).context("failed to decode base32")
}

pub fn gen_wg_keypair() -> (String, String) {
    let csprng = OsRng {};
    let sk = StaticSecret::random_from_rng(csprng);
    let pk = PublicKey::from(&sk);
    (base64.encode(pk.to_bytes()), base64.encode(sk.to_bytes()))
}

pub fn gen_public_key_from_private(private_key: &String) -> Result<String> {
    let key = base64
        .decode(private_key)
        .with_context(|| format!("failed to base64 decode private key {private_key}"))?;
    let key: [u8; 32] = key
        .try_into()
        .map_err(|_| anyhow!("private key has invalid length"))?;
    let sk = StaticSecret::from(key);
    let public_key = PublicKey::from(&sk);
    Ok(base64.encode(public_key.to_bytes()))
}

pub fn b64_decode_to_hex(s: &str) -> Result<String> {
    let data = base64
        .decode(s)
        .with_context(|| format!("failed to base64 decode string {s}"))?;
    let mut hex = String::new();
    for c in data {
        hex.push_str(format!("{c:02x}").as_str());
    }
    Ok(hex)
}

// Encrypt a password the way the official feilian client (v1 login, `/api/v1/login`)
// does, reverse-engineered from `wireguard.Wireguard.encryptByAesCbc(generateFixedString(), pwd)`
// in libgojni.so. Both key and IV are derived from fixed constants, so the output is
// deterministic and acts as a stable password hash on the server side.
//
//   KEY = hex(md5("9007199254740991"))   -> 32 ascii bytes (AES-256 key)
//   IV  = hex(sha1(KEY))[..16]            -> 16 ascii bytes
//   out = lower_hex( AES-256-CBC(KEY, IV, PKCS7(password)) )
pub fn feilian_v1_encrypt_password(password: &str) -> String {
    let key = format!("{:x}", md5::compute(b"9007199254740991"));
    let iv = hex::encode(Sha1::digest(key.as_bytes()));
    let iv = &iv[..16];

    let ct = cbc::Encryptor::<Aes256>::new(
        GenericArray::from_slice(key.as_bytes()),
        GenericArray::from_slice(iv.as_bytes()),
    )
    .encrypt_padded_vec_mut::<Pkcs7>(password.as_bytes());
    hex::encode(ct)
}
