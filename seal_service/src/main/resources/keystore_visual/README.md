# Visual Seal Certificates

Visual Seals require EC-Certificates (Elliptic Curves / ECDSA).

## Create Keystores

We create two separate keystores (PKCS12 format) for private keys and public certificates.

1) Create a CA key pair and certificate:

```
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -x509 -nodes -days 365 -out cert_001.pem -keyout key_001.pem -subj "/C=DE/ST=Berlin/L=Berlin/O=KMK/OU=ZAB/CN=ZAB"
```
2) Create PKCS#12 file "zab_visual_private.p12" containing the private keys:

```
openssl pkcs12 -export -nocerts -in cert_001.pem -inkey key_001.pem -name "001" -out zab_visual_private.p12 -passout pass:123456
```
3) Create (or extend) a PKCS#12 file "zab_visual_public.p12" containing the public keys:

```
keytool -importcert -alias 001 -file cert_001.pem -keystore zab_visual_public.p12 -storepass 123456 --noprompt
```
## Passwords

* For the end-entity keystore (zab_visual_private.p12), the password is 123456.
