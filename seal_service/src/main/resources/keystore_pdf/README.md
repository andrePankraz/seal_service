# PDF Seal Certificates

PDF Seals require RSA Certificates (PDF Signing with PAdES) with a complete chain.

## Import Keystores (D-Trust)

We create two separate keystores (PKCS12 format) for private keys and public certificates.

D-Trust delivers a pfx, which must be converted to p12.

1) Convert pfx to p12:

```
keytool -importkeystore -srckeystore zab_pdf_private.pfx -srcstoretype pkcs12 -destkeystore zab_pdf_private.p12 -deststoretype PKCS12 -srcalias 1 -destalias zab
```
Now you have a Java keystore named zab_pdf_private.p12 that contains the end-entity key pair and the certificate chain (root CA, intermediate CA, and end-entity certificates).

2) Create (or extend) a PKCS#12 file "zab_pdf_public.p12" containing the public keys (with the certificates serial numbers as alias):

```
openssl pkcs12 -in zab_pdf_private.p12 -nokeys -out zab_pdf_public.crt -passin pass:yourpassword
CERT_SERIAL_NUMBER=$(openssl x509 -in zab_pdf_public.crt -noout -serial | cut -d '=' -f 2)
keytool -import -file zab_pdf_public.crt -keystore ../keystore_pdf/zab_pdf_public.p12 -alias $CERT_SERIAL_NUMBER -storetype PKCS12 --noprompt
```
## Alternative: Create Keystores with temporary certificates

We create two separate keystores (PKCS12 format) for private keys and public certificates.

Caution: Temporary certificates will not validate correctly in Acrobat Reader, because the Root CA isn't known there as trusted entity.

1) Create a root CA key pair and certificate:

```
keytool -genkeypair -alias rootCA -keyalg RSA -keysize 2048 -dname "CN=Root CA, OU=ZAB, O=KMK, L=Berlin, ST=Berlin, C=DE" -validity 3650 -keystore rootCA.p12 -storetype pkcs12 -storepass rootCA_password -keypass rootCA_password
```
2) Create an intermediate CA key pair and a certificate signing request (CSR):

```
keytool -genkeypair -alias intermediateCA -keyalg RSA -keysize 2048 -dname "CN=Intermediate CA, OU=ZAB, O=KMK, L=Berlin, ST=Berlin, C=DE" -validity 3650 -keystore intermediateCA.p12 -storetype pkcs12 -storepass intermediateCA_password -keypass intermediateCA_password

keytool -certreq -alias intermediateCA -keystore intermediateCA.p12 -file intermediateCA.csr -storepass intermediateCA_password
```
3) Export the root CA certificate and private key:

```
keytool -exportcert -alias rootCA -keystore rootCA.p12 -rfc -file rootCA.pem -storepass rootCA_password
openssl pkcs12 -in rootCA.p12 -nocerts -nodes -password pass:rootCA_password -out rootCA.key
```
4) Sign the intermediate CA CSR with the root CA:

```
openssl x509 -req -CA rootCA.pem -CAkey rootCA.key -in intermediateCA.csr -out intermediateCA.pem -days 3650 -CAcreateserial -passin pass:rootCA_password
```
5) Import the root CA and signed intermediate CA certificates into the intermediate CA keystore:

```
keytool -importcert -alias rootCA -file rootCA.pem -keystore intermediateCA.p12 -storepass intermediateCA_password -noprompt
keytool -importcert -alias intermediateCA -file intermediateCA.pem -keystore intermediateCA.p12 -storepass intermediateCA_password
```
6) Create an end-entity key pair and a certificate signing request (CSR):

```
keytool -genkeypair -alias zab -keyalg RSA -keysize 2048 -dname "CN=ZAB, OU=ZAB, O=KMK, L=Berlin, ST=Berlin, C=DE" -validity 365 -keystore zab_pdf_private.p12 -storetype pkcs12 -storepass 123456 -keypass 123456

keytool -certreq -alias zab -keystore zab_pdf_private.p12 -file zab.csr -storepass 123456
```
7) Export the intermediate CA private key:

```
openssl pkcs12 -in intermediateCA.p12 -nocerts -nodes -password pass:intermediateCA_password -out intermediateCA.key
```
8) Sign the end-entity CSR with the intermediate CA:

```
openssl x509 -req -CA intermediateCA.pem -CAkey intermediateCA.key -in zab.csr -out zab.pem -days 365 -CAcreateserial -passin pass:intermediateCA_password
```
9) Import the root CA, intermediate CA, and signed end-entity certificates into the end-entity keystore:

```
keytool -importcert -alias rootCA -file rootCA.pem -keystore zab_pdf_private.p12 -storepass 123456 -noprompt
keytool -importcert -alias intermediateCA -file intermediateCA.pem -keystore zab_pdf_private.p12 -storepass 123456 -noprompt
keytool -importcert -alias zab -file zab.pem -keystore zab_pdf_private.p12 -storepass 123456
```
Now you have a Java keystore named zab_pdf_private.p12 that contains the end-entity key pair and the certificate chain (root CA, intermediate CA, and end-entity certificates).

10) Create (or extend) a PKCS#12 file "zab_pdf_public.p12" containing the public keys (with the certificates serial numbers as alias):

```
export CERT_SERIAL_NUMBER=$(openssl x509 -in zab.pem -noout -serial | cut -d '=' -f 2)
keytool -importcert -alias $CERT_SERIAL_NUMBER -file zab.pem -keystore zab_pdf_public.p12 -storepass 123456 --noprompt
```

## Passwords

* For the root CA keystore (rootCA.p12), the password is rootCA_password.
* For the intermediate CA keystore (intermediateCA.p12), the password is intermediateCA_password.
* For the end-entity keystore (zab_pdf_private.p12), the password is 123456.
