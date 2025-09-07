# jpegAuthentication
Cryptographic source authentication of JPEG images using IMEI + digital signature embedded in the COM segment (0xFFFE).

> Research prototype accompanying the paper:CRYPTOGRAPHIC SOURCE AUTHENTICATION OF JPEG IMAGES USING IMEI AND DIGITAL SIGNATURE EMBEDDED IN COM SEGMENT (David Arboledas Brihuega, Asociación Española de Imagen Científica y Forense).

---

## Table of contents
- [Overview](#overview)
- [Key features](#key-features)
- [How it works](#how-it-works)
- [On‑disk data format (COM payload)](#on-disk-data-format-com-payload)
- [CLI quickstart](#cli-quickstart)
- [Installation](#installation)
- [Verification workflow](#verification-workflow)
- [Threat model & limitations](#threat-model--limitations)
- [Privacy & legal (GDPR)](#privacy--legal-gdpr)
- [Roadmap](#roadmap)
- [Cite this work](#cite-this-work)
- [License](#license)

---

## Overview
`jpegAuthentication` provides a **low‑cost, device‑bound authenticity seal** for JPEG images at **capture time**. The system computes a hash of the image’s **visual payload** (JPEG bytes from SOS `0xFFDA` to EOI `0xFFD9`), concatenates it with the device **IMEI**, signs the string using the **manufacturer’s private key**, and embeds the result inside a standard **COM marker** (`0xFFFE`).

This design enables **offline, public‑key verification** of:

1. **Integrity** — the image’s visual content has not changed since capture.
2. **Provenance** — the image originated from a device with the stated IMEI.

It deliberately avoids heavy manifest ecosystems (e.g., C2PA/JUMBF) to favor **forensic, judicial, and field workflows** where simplicity, determinism, and independence from cloud infrastructure are required.

> ⚠️ **Security note**: The reference PoC uses MD5 for speed in demonstrations; **use SHA‑256 or SHA‑3 in production**. Keys should live in secure hardware (TPM / Secure Enclave) and never leave the device.

---

## Key features
- **Standards‑compatible**: Uses the JPEG COM segment; images remain viewable in any software.
- **Device binding**: Couples visual hash with **IMEI** to anchor provenance to physical hardware.
- **Offline verification**: Anyone with the **manufacturer’s public key** can verify.
- **Forensic‑aware hashing**: Hash covers only **visual payload** (SOS→EOI), excluding metadata and the COM block itself.
- **Minimal footprint**: Entire seal fits well under the COM capacity (~64 KB max payload).

---

## How it works
1. **Acquire** JPEG on device.
2. **Extract IMEI** using platform API (e.g., Android `TelephonyManager`) or ADB in forensic workflows.
3. **Compute hash** over bytes between SOS (`0xFFDA`) and EOI (`0xFFD9`).
4. **Concatenate** `IMEI || HASH` and **sign** with private key (RSA‑2048 or Ed25519/ECDSA‑P256 recommended).
5. **Embed** `{imei, hash, signature, alg, ts?}` as a **COM** segment placed before EOI.
6. **Verify** later by extracting COM, recomputing the visual hash, and checking the signature with the public key.

```
[SOI] ... [APPn/EXIF] ... [DQT][DHT][SOF] [SOS | 0xFFDA]  .. compressed data ..  [COM | 0xFFFE]  [EOI | 0xFFD9]
```

---

## On‑disk data format (COM payload)
JSON (UTF‑8) wrapped in the COM segment. Example:

```json
{
  "v": 1,
  "imei": "356789101234567",
  "hash_alg": "SHA-256",
  "hash": "b6c3…a9f0",          
  "sig_alg": "RSA-2048-PKCS1v1_5", 
  "sig": "base64:MIIB…",
  "ts": "2025-09-07T10:15:30Z",
  "pubkey_hint": "manufacturer:AcmeMobile:v1"
}
```

- **Placement**: just before EOI.
- **Length**: COM length field includes the 2‑byte length itself; payload capacity ≈ 65,533 bytes.
- **Encoding**: UTF‑8; binary signature is Base64‑encoded.

> Alternative encodings (CBOR) are supported experimentally to reduce size.

---

## CLI quickstart
> Requires Python 3.11+, OpenSSL (or PyCryptodome), and ADB for optional IMEI extraction.

**Seal a JPEG**
```bash
python tools/seal_jpeg.py   --in input.jpg   --out sealed.jpg   --imei 356789101234567   --privkey keys/private.pem   --hash sha256   --sig-alg rsa-pss
```

**Verify a sealed JPEG**
```bash
python tools/verify_jpeg.py   --in sealed.jpg   --pubkey keys/public.pem
```

**Extract IMEI via ADB (forensic workstation)**
```bash
adb shell service call iphonesubinfo 1
```

---

## Installation
```bash
# clone
git clone https://github.com/<your-org>/jpegAuthentication.git
cd jpegAuthentication

# create venv
python -m venv .venv && source .venv/bin/activate  # Windows: .venv\Scripts\activate

# deps
pip install -r requirements.txt  # e.g., pycryptodome, click
```

**Keys**
- Generate demo keys:
```bash
openssl genrsa -out keys/private.pem 2048
openssl rsa -in keys/private.pem -pubout -out keys/public.pem
```
- _Production_: keys should be generated and stored in TPM/Secure Enclave. Private key must be non‑exportable.

---

## Verification workflow
1. Parse JPEG; locate **COM**.
2. Decode JSON; read `imei`, `hash_alg`, `hash`, `sig`, `sig_alg`.
3. Recompute **visual hash** (SOS→EOI; exclude COM and APPn).
4. Verify signature over `imei || hash` using **manufacturer public key**.
5. Compare recomputed hash to stored hash.
6. Output **classification**:
   - ✅ **Authentic**: signature valid & hashes match.
   - ⚠️ **Questionable**: COM missing/corrupt; or unverifiable.
   - ❌ **Tampered**: signature invalid or hash mismatch.
   - ℹ️ **Partially Valid**: signature valid but IMEI unexpected.

---

## Threat model & limitations
**Adversary goals**: alter pixels; transplant seal; spoof IMEI; strip COM; forge signature.

**What we defend against**
- Pixel edits ⇒ **hash mismatch**.
- Seal transplant ⇒ mismatched visual hash.
- Fake signature ⇒ rejected by public‑key verification.

**Known limitations / critical discussion**
- **COM stripping**: Many platforms re‑encode or strip metadata/markers. Authenticity becomes **non‑verifiable** (treated as _Questionable_). This is a deliberate signal rather than silent failure.
- **Identifier choice (IMEI)**: IMEI is a **personal identifier** under GDPR when linkable to a person. Exposure requires minimization and access controls; consider **tokenization/blinding** in some deployments.
- **Key management**: Requires a trustworthy **public‑key directory** and revocation. Without it, verification trust is weaker than desired.
- **Hash scope**: Limiting to SOS→EOI defends the visual payload but not container‑level fields; this is intentional for forensic determinism, but differs from manifest approaches (C2PA/JUMBF) that preserve edit history.
- **PoC algorithms**: MD5 in demos is insecure; production must use **SHA‑256/3** and modern signatures (**RSA‑PSS / Ed25519 / ECDSA‑P‑256**).

**Relation to C2PA/JUMBF**
- This project is **complementary**: a minimal, offline seal for primary acquisition. It does **not** record edit provenance like C2PA.

---

## Privacy & legal (GDPR)
- Treat IMEI as **personal data** when linkable to an individual.
- Minimize: store only what is necessary; consider hashing/PRF of IMEI or encrypting the COM payload where lawful.
- Security: keys in TPM; audit access; chain‑of‑custody logs for forensic workflows.
- Jurisdictional review recommended before production use.

---

## Roadmap
- [ ] Replace MD5 in examples with **SHA‑256** end‑to‑end.
- [ ] Add **Ed25519** signing backend.
- [ ] Optional **timestamp** + signer app ID in payload.
- [ ] **CBOR** encoding option; size‑bounded payloads.
- [ ] Pluggable **IMEI blinding** (HMAC with device key).
- [ ] Packaging as Android native module / firmware hook.
- [ ] Verifier GUI and bulk‑verification API.
- [ ] Interop bridge to export a **JUMBF assertion** from COM payload.

---

## Cite this work
Arboledas Brihuega, D. _Cryptographic Source Authentication of JPEG Images Using IMEI and Digital Signature Embedded in COM Segment_. Asociación Española de Imagen Científica y Forense.

> You may also cite the associated repository: `jpegAuthentication` (GitHub), MIT License.

---

## License
MIT © David Arboledas Brihuega
