(async () => {

  createSignature()

  async function createSignature() {

    const privateKey = await importPrivateKey()
    console.log(privateKey)

    const data = str2ab("Test buffer")
    const sign = await window.crypto.subtle.sign({
      name: "ECDSA",
      hash: {
        name: "SHA-256"
      }
    }, privateKey, data)
    console.log("SIGNATURE: " + window.btoa(ab2str(sign)))

    const publicKey = await importPublicKey()
    console.log(publicKey)
    const verify = await window.crypto.subtle.verify({
      name: "ECDSA",
      hash: {
        name: "SHA-256"
      }
    }, publicKey, sign, data)
    console.log("VERIFY: " + verify)
  }

  // openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -x509 -nodes -days 365 -out cert.pem -keyout key.pem
  // Curve type prime256v1 works and is like secp256r1 (https://datatracker.ietf.org/doc/rfc4492/).
  // Curve type brainpoolP256r1 isn't supported in web crypto?!
  async function importPrivateKey() {
    const pem = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgP0Goy9ygACBpJgwS
aJZFA7DkwqtlQRoue3N3YGjIk2KhRANCAASQ0L2y1PrFl8qEPR5HOwyOManOKSSh
3fstzQJTDLMBRLUUhcR7+HQF7mFHUYzZYDIZZf2Uymtv2LtGEfK3m05F
-----END PRIVATE KEY-----`
    const pemHeader = "-----BEGIN PRIVATE KEY-----"
    const pemFooter = "-----END PRIVATE KEY-----"
    const pemContents = pem.substring(pemHeader.length, pem.length - pemFooter.length)
    const binaryDerString = window.atob(pemContents)
    const binaryDer = str2ab(binaryDerString)
    return await window.crypto.subtle.importKey("pkcs8", binaryDer, {
      name: "ECDSA",
      namedCurve: "P-256"
    }, true, ["sign"])
  }

  // openssl ec -in key.pem -pubout > pub-key.pem
  async function importPublicKey() {
    const pem = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEkNC9stT6xZfKhD0eRzsMjjGpzikk
od37Lc0CUwyzAUS1FIXEe/h0Be5hR1GM2WAyGWX9lMprb9i7RhHyt5tORQ==
-----END PUBLIC KEY-----`
    const pemHeader = "-----BEGIN PRIVATE KEY-----"
    const pemFooter = "-----END PRIVATE KEY-----"
    const pemContents = pem.substring(pemHeader.length, pem.length - pemFooter.length)
    const binaryDerString = window.atob(pemContents)
    const binaryDer = str2ab(binaryDerString)
    return await window.crypto.subtle.importKey("spki", binaryDer, {
      name: "ECDSA",
      namedCurve: "P-256"
    }, true, ["verify"])
  }

  function str2ab(str) {
    const buf = new ArrayBuffer(str.length)
    const bufView = new Uint8Array(buf)
    for (let i = 0, strLen = str.length; i < strLen; i++) {
      bufView[i] = str.charCodeAt(i)
    }
    return buf
  }

  function ab2str(buf) {
    return String.fromCharCode.apply(null, new Uint8Array(buf))
  }

})()
