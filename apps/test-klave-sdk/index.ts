import { HTTP, HttpRequest, JSON, Crypto, Notifier, Result } from "@klave/sdk";
import { GenerateKeyInput, ImportKeyInput, ExportKeyInput, TestInput, SimpleKeyNameInput, SignInput, VerifyInput, DecryptInput, EncryptInput, GetPublicKeyInput, DigestInput, NumberVect, NumberVectResult} from "./types";
import { success, error, ErrorMessage } from "./klave/types";
import { encode, decode } from 'as-base64/assembly';

/**
 * @transaction
 */
export function generateKey(input: GenerateKeyInput): void
{
    if (input.key.algorithm == "aes") {
        let result = Crypto.AES.generateKey(input.keyName);
        if (result.err) {
            let err = result.err as Error;
            error(err.message);
            return;
        }
        let key = result.data as Crypto.KeyAES;
        success(key.name);
    }
    else if (input.key.algorithm == "ecdsa") {
        let result = Crypto.ECDSA.generateKey(input.keyName);
        if (result.err) {
            let err = result.err as Error;
            error(err.message);
            return;
        }
        let key = result.data as Crypto.KeyECC;
        success(key.name);
    }
}

/**
 * @transaction
 */
export function importKey(input: ImportKeyInput): void
{
    let result = Crypto.Subtle.importKey(input.key.format, String.UTF8.encode(input.key.keyData, false), {namedCurve: 'P-256'} as Crypto.EcKeyGenParams, input.key.extractable, ["sign", "verify"]);
    if (result.err) {
        let err = result.err as Error;
        error(err.message);
        return;
    }
    let key = result.data as Crypto.CryptoKey;
    success(key.name);
    Crypto.Subtle.saveKey(key.name);
}

/**
 * @transaction
 */
export function getPublicKey(input: GetPublicKeyInput): void
{
    let keyECC = Crypto.ECDSA.getKey(input.keyName);
    if (!keyECC) {
        error("Issue retrieving the key");
        return;
    }
    let output = keyECC.getPublicKey();
    success(output.getPem());
}

/**
 * @query
 */
export function exportKey(input: ExportKeyInput): void
{
    let key = Crypto.Subtle.loadKey(input.keyName);
    if (!key)
    {
        error("Issue retrieving the key");
        return;
    }
    let output = Crypto.Subtle.exportKey(input.format, key.data as Crypto.CryptoKey);
    if (output.data)
    {
        let keyData = Uint8Array.wrap(output.data as ArrayBuffer);
        success(encode(keyData));
    }
}

/**
 * @query
 */
export function sign(input: SignInput): void
{
    let key = Crypto.ECDSA.getKey(input.keyName);
    if (key == null)
    {
        error("Issue retrieving the key");
        return;
    }
    let signEcc = key.sign(String.UTF8.encode(input.clearText, true));
    if (signEcc.data)
    {
        success(encode(Uint8Array.wrap(signEcc.data as ArrayBuffer)));
    }
}

/**
 * @query
 */
export function verify(input: VerifyInput): void
{
    let key = Crypto.ECDSA.getKey(input.keyName);
    if (key == null)
    {
        error("Issue retrieving the key");
        return;
    }
    let result = key.verify(String.UTF8.encode(input.clearText, true), decode(input.signatureB64).buffer);
    let err = result.err as Error;
    if (err)
    {
        error(err.message);
        return;
    }
    let verified = result.data as Crypto.SignatureVerification;
    if (verified.isValid === true)
    {
        success("Verification successful");
    }
    else
    {
        error("Verification failed");
    }
}

/**
 * @query
 */
export function encrypt(input: EncryptInput): void
{
    let key = Crypto.AES.getKey(input.keyName);
    if (key == null)
    {
        error("Issue retrieving the key");
        return;
    }
    let result = key.encrypt(String.UTF8.encode(input.clearText, true));
    let err = result.err as Error;
    if (err)
    {
        error(err.message);
        return;
    }
    let output = result.data as ArrayBuffer;
    if (output)
    {
        success(encode(Uint8Array.wrap(output)));
    }
}

/**
 * @query
 */
export function decrypt(input: DecryptInput): void
{
    let key = Crypto.AES.getKey(input.keyName);
    if (key == null)
    {
        error("Issue retrieving the key");
        return;
    }
    let result = key.decrypt(decode(input.cipherTextB64).buffer);
    let err = result.err as Error;
    if (err)
    {
        error(err.message);
        return;
    }
    let output = result.data as ArrayBuffer;
    if (output)
    {
        success(encode(Uint8Array.wrap(output)));
    }
}

/**
 * @query
 */
export function digest(input: DigestInput): void
{
    let result = Crypto.SHA.digest(input.algorithm, String.UTF8.encode(input.clearText, true));
    let err = result.err as Error;
    if (err)
    {
        error(err.message);
        return;
    }
    let output = result.data as ArrayBuffer;
    if (output)
    {
        success(encode(Uint8Array.wrap(output)));
    }
}


/**
 * @transaction
 */
export function testECDSA_256_PKCS8_SC(input: TestInput): void
{
    let key: Result<Crypto.CryptoKey, Error>;
    if (!input.useDefault) {
        key = Crypto.Subtle.generateKey({namedCurve: 'P-256'} as Crypto.EcKeyGenParams, true, ['sign', 'verify'], "ECDSA_256_PKCS8_SC_Key1");
        let err = key.err as Error;
        if (err) {
            error(err.message);
            return;
        }
    }
    else {
        let privateKeyStr = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgTt/Y3m9s0+rVTqnZruGG4zZy4N95uQEj5WTnyZD6p5KhRANCAAR5cjZzyTG+k6FlMs+Igo+mhiC1LOKMl+yg7qpdur6m3GlEpy/4whpA6xi2UnBH9PQsiY5r1xxgivn48YgfuC5h";
        key = Crypto.Subtle.importKey('pkcs8', String.UTF8.encode(privateKeyStr), {namedCurve: 'P-256'} as Crypto.EcKeyGenParams, true, ["sign", "verify"], "ECDSA_256_PKCS8_SC_Key2");
        let err = key.err as Error;
        if (err) {
            error(err.message);
            return;
        }
    }
    let keyData = key.data as Crypto.CryptoKey;
    if (keyData) {
        success(keyData.name);
    }

    let publicData = Crypto.Subtle.getPublicKey(keyData);
    let err = publicData.err as Error;
    if (err) {
        error(err.message);
        return;
    }
    let pubData = publicData.data as ArrayBuffer;
    if (pubData)
    {
        success(encode(Uint8Array.wrap(pubData)));
    }

    let pkcs8Key = Crypto.Subtle.exportKey('pkcs8', keyData);
    err = pkcs8Key.err as Error;
    if (err) {
        error(err.message);
        return;
    }
    let pkcs8Data = pkcs8Key.data as ArrayBuffer;
    if (pkcs8Data)
    {
        success(encode(Uint8Array.wrap(pkcs8Data)));
    }

    let sec1Key = Crypto.Subtle.exportKey('sec1', key.data);
    err = sec1Key.err as Error;
    if (err) {
        error(err.message);
        return;
    }
    let sec1Data = sec1Key.data as ArrayBuffer;
    if (sec1Data)
    {
        success(encode(Uint8Array.wrap(sec1Data)));
    }

    let pubKey = Crypto.Subtle.exportKey('spki', key.data);
    err = pubKey.err as Error;
    if (err) {
        error(err.message);
        return;
    }
    let pubKeyData = pubKey.data as ArrayBuffer;
    if (pubKeyData)
    {
        success(encode(Uint8Array.wrap(pubKeyData)));
    }
    else {
        error("Cannot export public key from private key. Do use getPublicKey().");
    }

    let ecdsaParams = {hash: "SHA2-256"} as Crypto.EcdsaParams;
    let signature = Crypto.Subtle.sign(ecdsaParams, key.data, String.UTF8.encode("Hello World"));
    err = signature.err as Error;
    if (err) {
        error(err.message);
        return;
    }
    let signData = signature.data as ArrayBuffer;
    if (signData)
    {
        let verified = Crypto.Subtle.verify(ecdsaParams, key.data, String.UTF8.encode("Hello World"), signData);
        if (verified) {
            success("ECDSA_256_PKCS8_SC test passed");
        }
    }
}

/**
 * @transaction
 */
export function testECDSA_256_SEC1_SC(input: TestInput): void
{
    let key: Result<Crypto.CryptoKey, Error>;
    if (!input.useDefault) {
        key = Crypto.Subtle.generateKey({namedCurve: 'P-256'} as Crypto.EcKeyGenParams, true, ['sign', 'verify'], "ECDSA_256_SEC1_SC_Key1");
        let err = key.err as Error;
        if (err) {
            error(err.message);
            return;
        }
    }
    else {
        let privateKey = "MHcCAQEEIE7f2N5vbNPq1U6p2a7hhuM2cuDfebkBI+Vk58mQ+qeSoAoGCCqGSM49AwEHoUQDQgAEeXI2c8kxvpOhZTLPiIKPpoYgtSzijJfsoO6qXbq+ptxpRKcv+MIaQOsYtlJwR/T0LImOa9ccYIr5+PGIH7guYQ==";
        key = Crypto.Subtle.importKey('sec1', String.UTF8.encode(privateKey), {namedCurve: 'P-256'} as Crypto.EcKeyGenParams, true, ["sign", "verify"], "ECDSA_256_SEC1_SC_Key2");
        let err = key.err as Error;
        if (err) {
            error(err.message);
            return;
        }
    }
    let keyData = key.data as Crypto.CryptoKey;
    if (keyData) {
        success(keyData.name);
    }

    let publicData = Crypto.Subtle.getPublicKey(keyData);
    let err = publicData.err as Error;
    if (err) {
        error(err.message);
        return;
    }
    let pubData = publicData.data as ArrayBuffer;
    if (pubData)
    {
        success(encode(Uint8Array.wrap(pubData)));
    }

    let pkcs8Key = Crypto.Subtle.exportKey('pkcs8', keyData);
    err = pkcs8Key.err as Error;
    if (err) {
        error(err.message);
        return;
    }
    let pkcs8Data = pkcs8Key.data as ArrayBuffer;
    if (pkcs8Data)
    {
        success(encode(Uint8Array.wrap(pkcs8Data)));
    }

    let sec1Key = Crypto.Subtle.exportKey('sec1', key.data);
    err = sec1Key.err as Error;
    if (err) {
        error(err.message);
        return;
    }
    let sec1Data = sec1Key.data as ArrayBuffer;
    if (sec1Data)
    {
        success(encode(Uint8Array.wrap(sec1Data)));
    }

    let pubKey = Crypto.Subtle.exportKey('spki', key.data);
    err = pubKey.err as Error;
    if (err) {
        error(err.message);
        return;
    }
    let pubKeyData = pubKey.data as ArrayBuffer;
    if (pubKeyData)
    {
        success(encode(Uint8Array.wrap(pubKeyData)));
    }
    else {
        error("Cannot export public key from private key. Do use getPublicKey().");
    }

    let ecdsaParams = {hash: "SHA2-256"} as Crypto.EcdsaParams;
    let signature = Crypto.Subtle.sign(ecdsaParams, key.data, String.UTF8.encode("Hello World"));
    err = signature.err as Error;
    if (err) {
        error(err.message);
        return;
    }
    let signData = signature.data as ArrayBuffer;
    if (signData)
    {
        let verified = Crypto.Subtle.verify(ecdsaParams, key.data, String.UTF8.encode("Hello World"), signData);
        if (verified) {
            success("ECDSA_256_PKCS8_SC test passed");
        }
    }
}

/**
 * @transaction
 */
export function testECDSA_256_PKCS8_KeyECC(input: TestInput): void
{
    let keyName: string = "";
    if (!input.useDefault) {
        let key1 = Crypto.ECDSA.generateKey("ECDSA_256_PKCS8_KeyECC_Key1");
        let err = key1.err as Error;
        if (err) {
            error(err.message);
            return;
        }
        let keyData = key1.data as Crypto.KeyECC;
        if (keyData) {
            keyName = keyData.name;
        }
    }
    else {
        let privateKey = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgTt/Y3m9s0+rVTqnZruGG4zZy4N95uQEj5WTnyZD6p5KhRANCAAR5cjZzyTG+k6FlMs+Igo+mhiC1LOKMl+yg7qpdur6m3GlEpy/4whpA6xi2UnBH9PQsiY5r1xxgivn48YgfuC5h";
        let key2 = Crypto.Subtle.importKey("pkcs8", String.UTF8.encode(privateKey), {namedCurve: 'P-256'} as Crypto.EcKeyGenParams, true, ['sign', 'verify'], "ECDSA_256_PKCS8_KeyECC_Key2");
        let err = key2.err as Error;
        if (err) {
            error(err.message);
            return;
        }
        let keyData = key2.data as Crypto.CryptoKey;
        if (keyData) {
            keyName = keyData.name;
        }
    }
    success(keyName);

    let key = Crypto.ECDSA.getKey(keyName);
    if (!key) {
        error("Issue retrieving the key" + keyName);
        return;
    }
    let spki_pem = key.getPublicKey().getPem();
    success(spki_pem);

    let signature = key.sign(String.UTF8.encode("Hello World"));
    let err = signature.err as Error;
    if (err) {
        error(err.message);
        return;
    }
    let signData = signature.data as ArrayBuffer;
    if (signData)
    {
        let verifyResult = key.verify(String.UTF8.encode("Hello World"), signData);
        err = verifyResult.err as Error;
        if (err) {
            error(err.message);
            return;
        }
        let verifyData = verifyResult.data as Crypto.SignatureVerification;
        if (verifyData.isValid === true) {  
            success("ECDSA_256_PKCS8_KeyECC test passed");
        }
    }
}

/**
 * @transaction
 */
export function testECDSA_384_PKCS8_SC(input: TestInput): void
{
    let key: Result<Crypto.CryptoKey, Error>;
    if (!input.useDefault) {
        key = Crypto.Subtle.generateKey({namedCurve: 'P-384'} as Crypto.EcKeyGenParams, true, ['sign', 'verify'], "ECDSA_384_PKCS8_SC_Key1");
        let err = key.err as Error;
        if (err) {
            error(err.message);
            return;
        }
    }
    else {
        let privateKey = "MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDAQZxlf/3lwVVda6CTmi/6IVwq9/ph6+PP4pXZLDm2mqkteZnSG++3b5WvB8cNR5B+hZANiAARzmnpXrdUIRGcy/Ibh6f1erNaOhUvla929Qzfow0Gb3veXSEeo0A+HboAsX+jVIemwKy/Tvx7yP8gcSw5x8Cz2Ytg3h8vNsHP8XUts4Bm5bSxMoTQAP5ctE8cTP54oShY=";
        key = Crypto.Subtle.importKey('pkcs8', String.UTF8.encode(privateKey), {namedCurve: 'P-384'} as Crypto.EcKeyGenParams, true, ['sign', 'verify'], "ECDSA_384_PKCS8_KeyECC_Key2");
        let err = key.err as Error;
        if (err) {
            error(err.message);
            return;
        }
    }
    let keyData = key.data as Crypto.CryptoKey;
    if (keyData) {
        success(keyData.name);
    }

    let publicData = Crypto.Subtle.getPublicKey(key.data);
    let err = publicData.err as Error;
    if (err) {
        error(err.message);
        return;
    }
    let pubData = publicData.data as ArrayBuffer;
    if (pubData)
    {
        success(encode(Uint8Array.wrap(pubData)));
    }

    let pkcs8Key = Crypto.Subtle.exportKey('pkcs8', key.data);
    err = pkcs8Key.err as Error;
    if (err) {
        error(err.message);
        return;
    }
    let pkcs8Data = pkcs8Key.data as ArrayBuffer;
    if (pkcs8Data)
    {
        success(encode(Uint8Array.wrap(pkcs8Data)));
    }

    let sec1Key = Crypto.Subtle.exportKey('sec1', key.data);
    err = sec1Key.err as Error;
    if (err) {
        error(err.message);
        return;
    }
    let sec1Data = sec1Key.data as ArrayBuffer;
    if (sec1Data)
    {
        success(encode(Uint8Array.wrap(sec1Data)));
    }

    let pubKey = Crypto.Subtle.exportKey('spki', key.data);
    err = pubKey.err as Error;
    if (err) {
        error(err.message);
        return;
    }
    let pubKeyData = pubKey.data as ArrayBuffer;
    if (pubKeyData)
    {
        success(encode(Uint8Array.wrap(pubKeyData)));
    }
    else {
        error("Cannot export public key from private key. Do use getPublicKey().");
    }

    let ecdsaParams = {hash: "SHA2-384"} as Crypto.EcdsaParams;
    let signature = Crypto.Subtle.sign(ecdsaParams, key.data, String.UTF8.encode("Hello World"));
    err = signature.err as Error;
    if (err) {
        error(err.message);
        return;
    }
    let signData = signature.data as ArrayBuffer;
    if (signData)
    {
        let verified = Crypto.Subtle.verify(ecdsaParams, key.data, String.UTF8.encode("Hello World"), signData);
        if (verified) {
            success("ECDSA_384_PKCS8_SC test passed");
        }
    }
}

/**
 * @transaction
 */
export function testECDSA_521_PKCS8_KeyECC(input: TestInput): void
{
    let key: Result<Crypto.CryptoKey, Error>;
    if (!input.useDefault) {
        key = Crypto.Subtle.generateKey({namedCurve: 'P-521'} as Crypto.EcKeyGenParams, true, ['sign', 'verify'], "ECDSA_521_PKCS8_SC_Key1");
        let err = key.err as Error;
        if (err) {
            error(err.message);
            return;
        }
    }
    else {
        let privateKey = "MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIA+dv0qK5sFDxMRPWGogkUbOAaZ/JURhljECO3hCfrj5ivSSgJaejSjdWFaebWfxBSFPkyTGfNemTaAWcNaBAlstahgYkDgYYABAB0TjLBB9top4MBjRD2djBxBlwvRqVoLeQPomOx6BlS5w5uZjWGdPOxJutXc9bYNw/ijgCGmWBxDtM5KOHGi5M1KACNQ43MLsalSsuPoHArH+9YnOyd/4wI9fnZTsmuaFOXV0NxNA4osW8eGYSZOUcQvAfGgNLTGYUmdYm/2sj/2kZlGA==";
        key = Crypto.Subtle.importKey('pkcs8', String.UTF8.encode(privateKey), {namedCurve: 'P-521'} as Crypto.EcKeyGenParams, true, ['sign', 'verify'], "ECDSA_521_PKCS8_KeyECC_Key2");
        let err = key.err as Error;
        if (err) {
            error(err.message);
            return;
        }
    }
    let keyData = key.data as Crypto.CryptoKey;
    if (keyData) {
        success(keyData.name);
    }

    let publicData = Crypto.Subtle.getPublicKey(key.data);
    let err = publicData.err as Error;
    if (err) {
        error(err.message);
        return;
    }
    let pubData = publicData.data as ArrayBuffer;
    if (pubData)
    {
        success(encode(Uint8Array.wrap(pubData)));
    }

    let pkcs8Key = Crypto.Subtle.exportKey('pkcs8', key.data);
    err = pkcs8Key.err as Error;
    if (err) {
        error(err.message);
        return;
    }
    let pkcs8Data = pkcs8Key.data as ArrayBuffer;
    if (pkcs8Data)
    {
        success(encode(Uint8Array.wrap(pkcs8Data)));
    }

    let sec1Key = Crypto.Subtle.exportKey('sec1', key.data);
    err = sec1Key.err as Error;
    if (err) {
        error(err.message);
        return;
    }
    let sec1Data = sec1Key.data as ArrayBuffer;
    if (sec1Data)
    {
        success(encode(Uint8Array.wrap(sec1Data)));
    }

    let pubKey = Crypto.Subtle.exportKey('spki', key.data);
    err = pubKey.err as Error;
    if (err) {
        error(err.message);
        return;
    }
    let pubKeyData = pubKey.data as ArrayBuffer;
    if (pubKeyData)
    {
        success(encode(Uint8Array.wrap(pubKeyData)));
    }
    else {
        error("Cannot export public key from private key. Do use getPublicKey().");
    }

    let ecdsaParams = {hash: "SHA2-512"} as Crypto.EcdsaParams;
    let signature = Crypto.Subtle.sign(ecdsaParams, key.data, String.UTF8.encode("Hello World"));
    err = signature.err as Error;
    if (err) {
        error(err.message);
        return;
    }
    let signData = signature.data as ArrayBuffer;
    if (signData)
    {
        let verified = Crypto.Subtle.verify(ecdsaParams, key.data, String.UTF8.encode("Hello World"), signData);
        if (verified) {
            success("ECDSA_521_PKCS8_SC test passed");
        }
    }
}

/**
 * @transaction
 */
export function testAES_128_RAW_KeyAES(input: TestInput): void
{
    let keyName: string = "";
    if (!input.useDefault) {
        let key1 = Crypto.AES.generateKey("AES_128_RAW_KeyAES_Key1");
        let err = key1.err as Error;
        if (err) {
            error(err.message);
            return;
        }
        let keyData = key1.data as Crypto.KeyAES;
        if (keyData) {
            keyName = keyData.name;
        }
    }
    else {
        let privateKey = "ZY7JOr1r8ms1Z9fsFl8VsQ==";
        let key2 = Crypto.Subtle.importKey("raw", String.UTF8.encode(privateKey), {length: 128} as Crypto.AesKeyGenParams, true, ['decrypt', 'encrypt'], "AES_128_RAW");
        let err = key2.err as Error;
        if (err) {
            error(err.message);
            return;
        }
        let keyData = key2.data as Crypto.CryptoKey;
        if (keyData) {
            keyName = keyData.name;
        }

    }

    success(keyName);

    let cryptoKey = Crypto.AES.getKey(keyName);
    if (!cryptoKey) {
        error("Issue retrieving the key" + keyName);
        return;
    }

    let encrypted_data = cryptoKey.encrypt(String.UTF8.encode("Hello World"));
    let err = encrypted_data.err as Error;
    if (err) {
        error(err.message);
        return;
    }
    let cipherText = encrypted_data.data as ArrayBuffer;
    if (cipherText)
    {
        success(encode(Uint8Array.wrap(cipherText)));
    }

    let clear_text = cryptoKey.decrypt(cipherText);
    err = clear_text.err as Error;
    if (err) {
        error(err.message);
        return;
    }
    let clearText = clear_text.data as ArrayBuffer;
    if (clearText)
    {
        success(encode(Uint8Array.wrap(clearText)));
    }
}

/**
 * @transaction
 */
export function testAES_128_RAW_KeyAES_external_key(input: SimpleKeyNameInput): void
{
    let keyName: string = input.keyName;
    success(keyName);

    let aesKey = Crypto.AES.getKey(keyName);
    if (!aesKey) {
        error("Issue retrieving the key" + keyName);
        return;
    }

    let cryptoKey = Crypto.Subtle.loadKey(keyName);
    let k = Crypto.Subtle.exportKey("raw", cryptoKey.data as Crypto.CryptoKey);
    let err = k.err as Error;
    if (err) {
        error(err.message);
        return;
    }
    let keyData = k.data as ArrayBuffer;
    if (keyData)
    {
        success(encode(Uint8Array.wrap(keyData)));
    }

    let encrypted_data = aesKey.encrypt(String.UTF8.encode("Hello World"));
    err = encrypted_data.err as Error;
    if (err) {
        error(err.message);
        return;
    }
    let cipherText = encrypted_data.data as ArrayBuffer;
    if (cipherText)
    {
        let clear_text = aesKey.decrypt(cipherText);
        err = clear_text.err as Error;
        if (err) {
            error(err.message);
            return;
        }
        let clearText = clear_text.data as ArrayBuffer;
        if (clearText)
        {
            success(encode(Uint8Array.wrap(clearText)));
        }
    }
}

/**
 * @transaction
 */
export function testSHA_256(input: TestInput): void
{
    //From https://emn178.github.io/online-tools/sha256.html
    let message = "Hello World";
    let expected_hash = "pZGm1Av0IEBKARczz7exkNYsZb8LzaMrV7J32a2fFG4=";

    let result = Crypto.SHA.digest("sha256", String.UTF8.encode(message));
    let err = result.err as Error;
    if (err) {
        error(err.message);
        return;
    }
    let digest = result.data as ArrayBuffer;
    if (digest)
    {
        success("testSHA_256 test passed");
    }
    else {
        error("testSHA_256 test failed: digest(" + encode(Uint8Array.wrap(digest)) + ") != expected_hash(" + expected_hash + ")" );
    }
}

/**
 * @transaction
 */
export function testSHA3_256(input: TestInput): void
{
    //From https://emn178.github.io/online-tools/sha3_256.html
    let message = "Hello World";
    let expected_hash = "4Wf2jWVj11uyXzqknCnvYS1BNS3ABgbefL1jC7JmX1E=";

    let result = Crypto.SHA.digest("sha3-256", String.UTF8.encode(message));
    let err = result.err as Error;
    if (err) {
        error(err.message);
        return;
    }
    let digest = result.data as ArrayBuffer;
    if (digest)
    {
        success("testSHA3_256 test passed");
    }
    else {
        error("testSHA3_256 test failed: digest(" + encode(Uint8Array.wrap(digest)) + ") != expected_hash(" + expected_hash + ")" );
    }
}

/**
 * @query
 */
export function grabRandomNumbers(input: TestInput): void
{
    const query: HttpRequest = {
        hostname: 'www.randomnumberapi.com',
        port: 443,
        path: '/api/v1.0/random?min=100&max=1000&count=5',
        headers: [],
        body: ''
    };

    const response = HTTP.request(query);
    if (!response) {
        Notifier.sendJson<ErrorMessage>({
            success: false,
            message: `HTTP call went wrong !`
        });
        return;
    }

    Notifier.sendString(response.body);
}

/**
 * @query
 */
export function grabBitcoinPrice(): void {

    const query: HttpRequest = {
        hostname: 'api.coindesk.com',
        port: 443,
        path: '/v1/bpi/currentprice.json',
        headers: [],
        body: ''
    };
    const response = HTTP.request(query);
    if (!response) {
        Notifier.sendJson<ErrorMessage>({
            success: false,
            message: `HTTP call went wrong !`
        });
        return;
    }

    Notifier.sendString(response.body);
};