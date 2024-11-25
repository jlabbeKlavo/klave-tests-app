import { JSON } from "@klave/sdk";

@JSON
export class KeyInput {
    format: string;         // raw, spki, pkcs8, jwk, sec1, 
    keyData: string;        // base64 encoded
    algorithm: string;      // ECDSA, AES-GCM, RSA-PSS,
    extractable: boolean;
    usages: string[];
}

@JSON
export class GenerateKeyInput {
    keyName: string;
    key: KeyInput;
}

@JSON
export class ImportKeyInput {
    keyName: string;
    key: KeyInput;
}

@JSON
export class GetPublicKeyInput {
    keyName: string;
    format: string;
}

@JSON
export class ExportKeyInput {
    keyName: string;
    format: string;
}

@JSON
export class SignInput {
    keyName: string;
    clearText: string;
}

@JSON
export class VerifyInput {
    keyName: string;
    clearText: string;
    signatureB64: string;
}

@JSON
export class EncryptInput {
    keyName: string;
    clearText: string;    
}

@JSON
export class DecryptInput {
    keyName: string;
    cipherTextB64: string;
}

@JSON
export class DigestInput {
    algorithm: string;
    clearText: string;
}

@JSON
export class TestInput {
    useDefault: boolean;        
}

@JSON
export class SimpleKeyNameInput {      
    keyName: string;
}

@JSON
export class NumberVect {
    vect!: i32[];
}
 
@JSON
export class NumberVectResult {
    success!: boolean;
    vect!: NumberVect;
}