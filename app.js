/*
 * *© Copyright 2021 Visa. All Rights Reserved.**
 *
 * NOTICE: The software and accompanying information and documentation (together, the “Software”) remain the property of
 * and are proprietary to Visa and its suppliers and affiliates. The Software remains protected by intellectual property
 * rights and may be covered by U.S. and foreign patents or patent applications. The Software is licensed and not sold.*
 *
 * By accessing the Software you are agreeing to Visa's terms of use (developer.visa.com/terms) and privacy policy (developer.visa.com/privacy).
 * In addition, all permissible uses of the Software must be in support of Visa products, programs and services provided
 * through the Visa Developer Program (VDP) platform only (developer.visa.com). **THE SOFTWARE AND ANY ASSOCIATED
 * INFORMATION OR DOCUMENTATION IS PROVIDED ON AN “AS IS,” “AS AVAILABLE,” “WITH ALL FAULTS” BASIS WITHOUT WARRANTY OR
 * CONDITION OF ANY KIND. YOUR USE IS AT YOUR OWN RISK.** All brand names are the property of their respective owners, used for identification purposes only, and do not imply
 * product endorsement or affiliation with Visa. Any links to third party sites are for your information only and equally
 * do not constitute a Visa endorsement. Visa has no insight into and control over third party content and code and disclaims
 * all liability for any such components, including continued availability and functionality. Benefits depend on implementation
 * details and business factors and coding steps shown are exemplary only and do not reflect all necessary elements for the
 * described capabilities. Capabilities and features are subject to Visa’s terms and conditions and may require development,
 * implementation and resources by you based on your business and operational details. Please refer to the specific
 * API documentation for details on the requirements, eligibility and geographic availability.*
 *
 * This Software includes programs, concepts and details under continuing development by Visa. Any Visa features,
 * functionality, implementation, branding, and schedules may be amended, updated or canceled at Visa’s discretion.
 * The timing of widespread availability of programs and functionality is also subject to a number of factors outside Visa’s control,
 * including but not limited to deployment of necessary infrastructure by issuers, acquirers, merchants and mobile device manufacturers.
 *
 *
 *  This sample code is licensed only for use in a non-production environment for sandbox testing. See the license for all terms of use.
 */
const express = require('express');
const jose = require('node-jose');
const fileUpload = require('express-fileupload');
const cors = require('cors');
const morgan = require('morgan');
const bodyParser = require('body-parser');
const crypto = require('crypto-js')

const app = express();
app.use(fileUpload({
    createParentPath: true
}));

app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));
app.use(morgan('dev'));

const swaggerUi = require('swagger-ui-express'),
    swaggerDocument = require('./public/swagger.json');

app.use(
    '/api-docs',
    swaggerUi.serve,
    swaggerUi.setup(swaggerDocument)
);

app.get('/', function (req, res) {
    res.redirect('/api-docs')
});


/**
 * This endpoint will encrypt the payload and create a JWE
 */
app.post('/rest/api/createJweUsingRsaPki', function (req, res) {
    const payload = req.body.payload;
    const encryptionKid = req.body.vEncryptionKid;
    let certificatePem = req.body.vEncryptionCertificatePem;
    let encData;
    try {
        if (req.files) {
            certificatePem = req.files.vEncryptionCertificateFile.data.toString();
        }
        jose.JWK.asKey(certificatePem, 'PEM', {
            "kty": "RSA",
            "alg": "RSA-OAEP-256",
            "kid": encryptionKid,
            enc: "A128GCM",
            key_opts: ["wrapKey", "enc"]
        }).then(function (result) {
            jose.JWE.createEncrypt({
                format: 'compact',
                contentAlg: 'A128GCM',
                fields: {iat: parseInt((Date.now() / 1000))}
            }, result).update(payload).final()
                .then(function (data) {
                    encData = data.toString();
                    res.setHeader('Content-Type', 'application/json');
                    res.send({"encData": encData});
                });
        }).catch(function (reason) {
            console.log('Encryption failed due to ');
            console.log(reason);
        });

    } catch (err) {
        console.log('Encryption failed due to ');
        console.log(err);
        res.status(500).send(err);
    }
});

/**
 * This endpoint will decrypt the JWE
 */
app.post('/rest/api/decryptJweUsingRsaPki', function (req, res) {
    const jwe = req.body.jwe;
    if (jwe.split("\.").length !== 5) {
        res.status(400).send({"message": "Data is not a JWE String"});
    } else {
        let privateKeyPem = req.body.privateKeyPem;
        try {
            if (req.files) {
                privateKeyPem = req.files.privateKeyFile.data.toString();
            }
            jose.JWK.asKey(privateKeyPem, 'PEM').then(function (result) {
                jose.JWE.createDecrypt(result).decrypt(jwe).then(function (decryptedResult) {
                    const decData = String(decryptedResult.plaintext);
                    res.setHeader('Content-Type', 'application/json');
                    res.send({"payload": decData});
                });
            }).catch(function (reason) {
                console.log('Decryption failed due to ');
                console.log(reason);
                res.status(400).send({"message": reason.message});
            });
        } catch
            (err) {
            console.log('Decryption failed due to ');
            console.log(err);
            res.status(500).send(err);
        }
    }
});

/**
 * This endpoint will sign the payload/JWE and create a JWS
 */
app.post('/rest/api/createJwsUsingRsaPki', function (req, res) {
    const jwe = req.body.jwe;
    const signingKid = req.body.signingKid;
    if (jwe.split("\.").length !== 5) {
        res.status(400).send({"message": "Data is not a JWE String"});
    } else {
        let privateKeyPem = req.body.privateKeyPem;
        try {
            if (req.files) {
                privateKeyPem = req.files.privateKeyFile.data.toString();
            }
            jose.JWK.asKey(privateKeyPem, 'PEM').then(function (result) {
                jose.JWS.createSign({
                    format: 'compact',
                    fields: {kid: signingKid, alg: 'PS256', cty: "JWE", typ: "JOSE"}
                }, result).update(jwe).final().then(function (jwsResult) {
                    let jws = String(jwsResult);
                    res.setHeader('Content-Type', 'application/json');
                    res.send({"encData": jws});
                });
            }).catch(function (reason) {
                console.log('Signing failed due to ');
                console.log(reason);
                res.status(400).send({"message": reason.message});
            });
        } catch
            (err) {
            console.log('Signing failed due to ');
            console.log(err);
            res.status(500).send(err);
        }
    }
});

/**
 * This endpoint will verify the JWS
 */
app.post('/rest/api/verifyJwsUsingRsaPki', function (req, res) {
    const jws = req.body.jws;
    if (jws.split("\.").length !== 3) {
        res.status(400).send({"message": "Data is not a JWS String"});
    } else {
        let signingCertificatePem = req.body.signingCertificatePem;
        try {
            if (req.files) {
                signingCertificatePem = req.files.signingCertificateFile.data.toString();
            }
            jose.JWK.asKey(signingCertificatePem, 'PEM').then(function (result) {
                jose.JWS.createVerify(result).verify(jws).then(function (jwsResult) {
                    res.setHeader('Content-Type', 'application/json');
                    res.send({"payload": String(jwsResult.payload), "verified": true});
                });
            }).catch(function (reason) {
                console.log('Signing failed due to ');
                console.log(reason);
                res.status(400).send({"message": reason.message, "verified": false});
            });
        } catch
            (err) {
            console.log('Signing failed due to ');
            console.log(err);
            res.status(500).send(err);
        }
    }
});

/**
 * This endpoint will encrypt the payload, creating the JWE and sign the JWE to create the JWS
 */
app.post('/rest/api/createJweJwsUsingRsaPki', function (req, res) {
    const payload = req.body.payload;
    const encryptionKid = req.body.vEncryptionKid;
    const signingKid = req.body.clientSigningKid;

    let certificatePem = req.body.vEncryptionCertificatePem;
    let privateKeyPem = req.body.clientSigningPrivateKeyPem;

    try {
        if (req.files) {
            certificatePem = req.files.vEncryptionCertificateFile.data.toString();
            privateKeyPem = req.files.clientSigningPrivateKeyFile.data.toString();
        }
        jose.JWK.asKey(certificatePem, 'PEM', {
            "kty": "RSA",
            "alg": "RSA-OAEP-256",
            "kid": encryptionKid,
            enc: "A128GCM",
            key_opts: ["wrapKey", "enc"]
        }).then(function (result) {
            jose.JWE.createEncrypt({
                format: 'compact',
                contentAlg: 'A128GCM',
                fields: {iat: parseInt((Date.now() / 1000))}
            }, result).update(payload).final()
                .then(function (data) {
                    const jwe = data.toString();
                    jose.JWK.asKey(privateKeyPem, 'PEM').then(function (result) {
                        jose.JWS.createSign({
                            format: 'compact',
                            fields: {kid: signingKid, alg: 'PS256', cty: "JWE", typ: "JOSE"}
                        }, result).update(jwe).final().then(function (jwsResult) {
                            let jws = String(jwsResult);
                            res.setHeader('Content-Type', 'application/json');
                            res.send({"encData": jws});
                        });
                    }).catch(function (reason) {
                        console.log('Signing failed due to ');
                        console.log(reason);
                        res.status(400).send({"message": reason.message});
                    });
                });
        }).catch(function (reason) {
            console.log('Encryption failed due to ');
            console.log(reason);
        });

    } catch (err) {
        console.log('Encryption failed due to ');
        console.log(err);
        res.status(500).send(err);
    }
});

/**
 * This endpoint will verify the JWS, extract the JWE and decrypt the JWE
 */
app.post('/rest/api/verifyAndDecryptUsingRsaPki', function (req, res) {
    const jws = req.body.jws;
    let visaSigningCertificatePem = req.body.vSigningCertificatePem;
    let clientPrivateKeyPem = req.body.clientPrivateKeyPem;

    if (!clientPrivateKeyPem.startsWith('-----BEGIN PRIVATE KEY-----')) {
        console.log('No a valid private key provided');
        res.status(400).send({"message": "No a valid private key provided"});
    } else if (jws.split("\.").length !== 3) {
        res.status(400).send({"message": "Data is not a JWS String"});
    } else {
        try {
            jose.JWK.asKey(visaSigningCertificatePem, 'PEM').then(function (result) {
                jose.JWS.createVerify(result).verify(jws).then(function (jwsResult) {
                    res.setHeader('Content-Type', 'application/json');
                    const jwe = String(jwsResult.payload);
                    jose.JWK.asKey(clientPrivateKeyPem, 'PEM').then(function (result) {
                        jose.JWE.createDecrypt(result).decrypt(jwe).then(function (decryptedResult) {
                            const decData = String(decryptedResult.plaintext);
                            res.setHeader('Content-Type', 'application/json');
                            res.send({"payload": decData, "verified": true});
                        });
                    }).catch(function (reason) {
                        console.log('Decryption failed due to ');
                        console.log(reason);
                        res.status(400).send({"message": reason.message, "verified": false});
                    });
                });
            }).catch(function (reason) {
                console.log('Signing failed due to ');
                console.log(reason);
                res.status(400).send({"message": reason.message, "verified": false});
            });
        } catch
            (err) {
            console.log('Signing failed due to ');
            console.log(err);
            res.status(500).send(err);
        }
    }
});

/**
 * This endpoint will encrypt the payload and create a JWE
 */
app.post('/rest/api/createJwe', function (req, res) {
    const payload = req.body.payload;
    const apiKey = req.body.apiKey;
    const sharedSecret = req.body.sharedSecret;
    res.setHeader('Content-Type', 'application/json');
    let encData;
    try {
        const sha256Hash = createSha256Hash(sharedSecret);
        jose.JWK.asKey({kty: 'oct', k: jose.util.asBuffer(sha256Hash, 'hex'), alg: "A256GCMKW", kid: apiKey})
            .then(function (key) {
                jose.JWE.createEncrypt({
                    format: 'compact',
                    contentAlg: 'A256GCM',
                    fields: {
                        enc: 'A256GCM'
                    }
                }, key).update(Buffer.from(payload)).final().then(function (data) {
                    encData = data.toString();
                    res.send({"encData": encData});
                });
            })
            .catch(function (err) {
                console.log('Encryption failed due to ');
                console.log(err);
                res.status(500).send({"message": err});
            });
    } catch (err) {
        console.log('Encryption failed due to ');
        console.log(err);
        res.status(500).send({"message": err});
    }
});

/**
 * This endpoint will decrypt the JWE
 */
app.post('/rest/api/decryptJwe', function (req, res) {
    const jwe = req.body.jwe;
    const sharedSecret = req.body.sharedSecret;
    res.setHeader('Content-Type', 'application/json');
    if (jwe.split("\.").length !== 5) {
        res.status(400).send({"message": "Data is not a JWE String"});
    } else {
        try {
            const sha256Hash = createSha256Hash(sharedSecret);
            jose.JWK.asKey({kty: 'oct', k: jose.util.asBuffer(sha256Hash, 'hex')})
                .then(function (key) {
                    jose.JWE.createDecrypt(key).decrypt(jwe)
                        .then(function (result) {
                            const payload = result.payload.toString();
                            res.send({"payload": payload});
                        })
                        .catch(function (err) {
                            console.log('Encryption failed due to ');
                            console.log(err);
                            res.status(500).send({"message": err.message});
                        });
                })
                .catch(function (err) {
                    console.log('Encryption failed due to ');
                    console.log(err);
                    res.status(500).send({"message": err.message});
                });
        } catch (err) {
            console.log('Encryption failed due to ');
            console.log(err);
            res.status(500).send({"message": err.message});
        }
    }
});

/**
 * This endpoint will sign the device binding request and generate the JWS
 */
app.post('/rest/api/signBindingRequest', function (req, res) {
    const clientDeviceID = req.body.clientDeviceID;
    const clientReferenceID = req.body.clientReferenceID;
    const vProvisionedTokenID = req.body.vProvisionedTokenID;
    const nonce = req.body.nonce;
    const signingKid = req.body.signingKid;
    let privateKeyPem = req.body.privateKeyPem;
    const payload = {
        "clientDeviceID": clientDeviceID,
        "clientReferenceID": clientReferenceID,
        "vProvisionedTokenID": vProvisionedTokenID,
        "nonce": nonce
    };
    try {
        if (req.files) {
            privateKeyPem = req.files.privateKeyFile.data.toString();
        }

        if (!privateKeyPem.startsWith('-----BEGIN PRIVATE KEY-----')) {
            console.log('No a valid private key provided');
            res.status(400).send({"message": "No a valid private key provided"});
        } else {
            jose.JWK.asKey(privateKeyPem, 'PEM').then(function (result) {
                jose.JWS.createSign({
                    format: 'compact',
                    fields: {kid: signingKid, alg: 'PS256', cty: "JWE", typ: "JOSE"}
                }, result).update(JSON.stringify(payload)).final().then(function (jwsResult) {
                    let jws = String(jwsResult);
                    res.setHeader('Content-Type', 'application/json');
                    res.send({"encData": jws});
                });
            }).catch(function (reason) {
                console.log('Signing failed due to ');
                console.log(reason);
                res.status(400).send({"message": reason.message});
            });
        }
    } catch
        (err) {
        console.log('Signing failed due to ');
        console.log(err);
        res.status(500).send(err);
    }
});

/**
 * Create a Sha256 Hash
 * @param str
 * @returns {*}
 */
function createSha256Hash(str) {
    return crypto.SHA256(str).toString(crypto.enc.Hex);
}

app.listen(3000, () => console.log(`Running... !`))