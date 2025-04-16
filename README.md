# Simple JWTs in Rust

This library allows for the signing and verifying of JWTs

## Generating a JWT

To generate a token you use `sign()` with your **Claims**, **Header** and **Signing Key**

Start by defining a `Claims` Struct. This struct will contain all of the data.
This struct must implement `serde::Serialize`, `serde::Deserialize` and `Clone` traits. Here is an example of a valid struct

```rust
#[derive(Serialize, Deserialize, Clone)]
pub struct Claims {
    pub exp: usize,
    pub id: String,
    pub role: String,
}
```

You must also create the header with your algorithm of choice.

```rust
let algorithm = Algorithm::HS256;
let header = Header::new(algorithm);
```

Then assuming you have read in your signing/private key from PEM format into a `String`

```rust
let signed_key = sign(header, claims, )
```

> [!NOTE]
> All keys should be read from **PEM format**, currently **only pkcs1 is supported**. See [this answer](https://stackoverflow.com/a/74575318/) for information on converting from pkcs8 using OpenSSL

## Verifying a JWT

We can verify a JWT signature is valid using the `verify()` function, with the **signed JWT** and your **verification (public) key**

> [!CAUTION]
> **No claims are verified in this function**, including `exp`. Only the signature is verified, the claims are returned to the caller to handle and verify.
> [!NOTE]
> All keys should be read from **PEM format**, currently **only pkcs1 is supported**. See [this answer](https://stackoverflow.com/a/74575318/) for information on converting from pkcs8 using OpenSSL

`verify()` returns the claims of the token assuming verification passes. The claims struct must be defined and requires the public key to be read in PEM pkcs1 format, as seen in [Generating a JWT](README.md/Generating-a-JWT)

Here is an example of using the `verify()` function:

```rust
let token = "pretend_this.is_a.valid_signed_token";
let public_key = "pretend_this_is_a_valid_public_key_from_a_pem_file";
let claims: Claims = verify(token, public_key).unwrap();
```
