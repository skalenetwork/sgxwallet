# API RPC Methods Specification

> ---
> ## Table of Contents
> ##### 1) ECDSA calls
>   1. [generateECDSAKey](#generateecdsakey) (TODO - complete)
>   2. [importECDSAKey](#importecdsakey) (TODO - complete & test)
>   3. [getPublicECDSAKey](#getpublicecdsakey)
>   4. [ecdsaSignMessageHash](#ecdsasignmessagehash)
> ##### 2) BLS calls
>   1. [importBLSKeyShare](#importblskeyshare)
>   2. [getBLSPublicKeyShare](#getblspublickeyshare) (TODO - complete description)
>   3. [blsSignMessageHash](#blssignmessagehash)
>   4. [createBLSPrivateKey](#createblsprivatekey) (TODO - complete & test)
>   5. [popProve](#popprove) (TODO - add description & parameter description)
>   6. [deleteBlsKey](#deleteblskey)
> ##### 3) DKG calls
>   1. [generateDKGPoly](#generatedkgpoly) 
>   2. [getVerificationVector](#getverificationvector)
>   3. [getSecretShareV2](#getsecretsharev2)
>   4. [dkgVerification](#dkgVerification) 
>   5. [isPolyExists](#ispolyexists)
> ##### 4) Threshold Encryption Calls
>   1. [getDecryptionShares](#getdecryptionshares)
> ##### 5) Server calls
>   1. [getServerStatus](#getserverstatus)
>   2. [getServerVersion](#getserverversion)
> ##### [6) Common Parameter Descriptions](#common-parameters-descriptions)
> ---


> TODO calls
> - getSecretShare
> - dkgVerificationV2
> - calculateAllBLSPublicKeys
> - complaintResponse
> - multG2
> - generateBLSPrivateKey
> - createBLSPrivateKeyV2

---

# 1) ECDSA Calls

## `generateECDSAKey`

#### Description
Generates a brand new ECDSA key, returning the public key.

#### Request Parameters
None


#### Example Request
```bash
curl -X POST --data '{ 
    "jsonrpc": "2.0", 
    "id": 1, 
    "method": "generateECDSAKey", 
    "params":null 
}' -H 'content-type:application/json;' -v --key ./sgx.key --cert ./sgx.crt https://127.0.0.1:1026 -k
```

#### Return values
| **Parameter** | **Type**   | **Description**                          |
|---------------|------------|------------------------------------------|
| `PublicKey`   | `String`   | Public ECDSA key created                 |
| `keyName`     | `String`   | [See ECDSA Key Name](#2-ecdsa-key-name)    |
|`encryptedKey` | `String`   | TODO    |

#### Example Response

```json
{
    "id":1,
    "jsonrpc":"2.0",
    "result":
    {
        "PublicKey":"11ffe920d1c66f2ad63bc1e972e7f89a088fae8c23b0adc84e2a5f04ff7f7e85bd7d934b225c57067c2ce4c0dab1bfdfc8f7682c661403fd151666f0683178e2",
        "encryptedKey":"d453d79860cca681371dac6fb19f13a042f49e762a2f29b737502fd9bd38558cff338335a0ede31bfb83df3579533a5cc4f769b0c3e2cd47cfd9f18f01174891daea608fd7b24ebb54f3926a80ed5ef6bffbad5040a8c51845ae7ce011decb",
        "errorMessage":"",
        "keyName":"NEK:2dfcf5ff6bcd93fbf45e5589afdf9c9dcff702e9beb5305506967b30a4f2da05",
        "publicKey":"11ffe920d1c66f2ad63bc1e972e7f89a088fae8c23b0adc84e2a5f04ff7f7e85bd7d934b225c57067c2ce4c0dab1bfdfc8f7682c661403fd151666f0683178e2",
        "status":0
    }
}
```

---

## `importECDSAKey`

TODO - need to test a request and response with a 'key' field that works

#### Description
Imports a previously generated key into the SGX, and associates it to the passed key name

#### Request Parameters
| **Parameter** | **Type**   | **Description**                          | **Example value**  |
|---------------|------------|------------------------------------------|--------------|
| `key`    | `String`  | Encrypted key in hexadecimal format - [See Message Hash](#4-message-hash) | TODO  |
| `keyName`    | `String`  | [See ECDSA Key Name](#2-ecdsa-key-name) | `NEK:2dfcf5ff6bcd93fbf45e5589afdf9c9dcff702e9beb5305506967b30a4f2da05`  |

#### Example Request
```bash
curl -X POST --data '{ 
    "jsonrpc": "2.0", 
    "id": 1, 
    "method": "importECDSAKey", 
    "params": {
        "key": "TODO"
        "keyName":"NEK:2dfcf5ff6bcd93fbf45e5589afdf9c9dcff702e9beb5305506967b30a4f2da05"
    } 
}' -H 'content-type:application/json;' -v --key ./sgx.key --cert ./sgx.crt https://127.0.0.1:1026 -k
```

#### Return Values
| **Parameter** | **Type**   | **Description**                          |
|---------------|------------|------------------------------------------|
| `encryptedKey`   | `String`   | public ECDSA key                         |

#### Example Response

```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result":
    {
        "encryptedKey": "TODO",
        "errorMessage": "TODO",
        "status": -30
    }
}
```

---



## `getPublicECDSAKey`

#### Description
Get the ECDSA public key given the key name. A key with the specified name must have been created prior to this call.

#### Request Parameters
| **Parameter** | **Type**   | **Description**                          | **Example value**  |
|---------------|------------|------------------------------------------|--------------|
| `keyName`    | `String`  | [See ECDSA Key Name](#2-ecdsa-key-name) | `NEK:2dfcf5ff6bcd93fbf45e5589afdf9c9dcff702e9beb5305506967b30a4f2da05`  |

#### Example Request
```bash
curl -X POST --data '{ 
    "jsonrpc": "2.0", 
    "id": 1, 
    "method": "getPublicECDSAKey", 
    "params": {
        "keyName":"NEK:2dfcf5ff6bcd93fbf45e5589afdf9c9dcff702e9beb5305506967b30a4f2da05"
    } 
}' -H 'content-type:application/json;' -v --key ./sgx.key --cert ./sgx.crt https://127.0.0.1:1026 -k
```

#### Return Values
| **Parameter** | **Type**   | **Description**                          |
|---------------|------------|------------------------------------------|
| `publicKey`   | `String`   | public ECDSA key                         |

#### Example Response

```json
{
    "id":1,
    "jsonrpc":"2.0",
    "result":
    {
        "PublicKey":"11ffe920d1c66f2ad63bc1e972e7f89a088fae8c23b0adc84e2a5f04ff7f7e85bd7d934b225c57067c2ce4c0dab1bfdfc8f7682c661403fd151666f0683178e2",
        "errorMessage":"",
        "publicKey":"11ffe920d1c66f2ad63bc1e972e7f89a088fae8c23b0adc84e2a5f04ff7f7e85bd7d934b225c57067c2ce4c0dab1bfdfc8f7682c661403fd151666f0683178e2",
        "status":0
    }
}
```

---

## `ecdsaSignMessageHash`

#### Description
Creates a signature for the passed hash using the key associated with the passed key name

#### Request Parameters
| **Parameter** | **Type**   | **Description**                          | **Example value**  |
|---------------|------------|------------------------------------------|--------------|
| `keyName`    | `String`  | [See ECDSA Key Name](#2-ecdsa-key-name) | `NEK:2dfcf5ff6bcd93fbf45e5589afdf9c9dcff702e9beb5305506967b30a4f2da05`  |
| `messageHash` | `String` | [See Message Hash](#4-message-hash) | `a65b656fd41907d71ea762` |
| `base` | `Unsigned Int` | Must be an integer value in the interval \([1, 32]\). If value is `16`, then the returned signature values are prefixed with `0x`. | 16

#### Example Request
```bash
curl -X POST --data '{ 
    "jsonrpc": "2.0", 
    "id": 1, 
    "method": "ecdsaSignMessageHash", 
    "params": { 
        "keyName": "NEK:2386174274cca0f14a383cfe03ea0da2ac89067bde464525779ade2d4a9572db",
        "messageHash": "a65b656fd41907d71ea762",
        "base": 16
    } 
}' -H 'content-type:application/json;' -v --key ./sgx.key --cert ./sgx.crt https://127.0.0.1:1026 -k
```

#### Return Values
| **Parameter** | **Type**   | **Description**                          |
|---------------|------------|------------------------------------------|
| `signature_r`   | `String`   | The x-coordinate of an elliptic curve point, derived from a random value. May or may not start with `0x`. |
| `signature_s`   | `String`   | A value ensuring message integrity, computed using the private key and `r`. May or may not start with `0x`. |
| `signature_v`   | `String`   | A recovery identifier used to determine the correct public key. |

#### Example Response

```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result":
    {
        "errorMessage": "",
        "signature_r": "0x2823b69311e75357f375036187319742fd1a05e7414077b670d8f51b60f82014",
        "signature_s": "0x6f48544e0d2d22fe4d2d6f23e56dbddcae9afd5be04fe42d0d2d8a6eee281bb0",
        "signature_v": "1",
        "status": 0
    }
}
```

---


# 2) BLS calls

## `importBLSKeyShare`

#### Description
TODO

#### Request Parameters
| **Parameter** | **Type**   | **Description**                          | **Example value**  |
|---------------|------------|------------------------------------------|--------------|
| `keyShareName`    | `String`  | [See BLS Key Name](#1-bls-key-name) | `BLS_KEY:SCHAIN_ID:0:NODE_ID:0:DKG_ID:1234`  |
| `keyShare`   | `String`    |  Any string of 64 hexadecimal characters (32-bytes total) | `4e9178241af6f1ecda046da2e3b03db893adb34f2d033a2f96e5a7b79a952f1d` |

#### Example Request
```bash
curl -X POST --data '{ 
    "jsonrpc": "2.0", 
    "id": 1, 
    "method": "importBLSKeyShare", 
    "params": { 
        "keyShareName": "BLS_KEY:SCHAIN_ID:0:NODE_ID:0:DKG_ID:1234", 
        "keyShare": "4e9178241af6f1ecda046da2e3b03db893adb34f2d033a2f96e5a7b79a952f1d" 
    } 
}' -H 'content-type:application/json;' -v --key ./sgx.key --cert ./sgx.crt https://127.0.0.1:1026 -k
```

#### Return Values
| **Parameter** | **Type**   | **Description**                          |
|---------------|------------|------------------------------------------|
| `encryptedKeyShare`   | `String`   | TODO |


#### Example Response

```json
{
    "id":1,
    "jsonrpc":"2.0",
    "result": 
    {
        "encryptedKeyShare":"186023fc74fc6748cfe306de8ffe1551ba79999c4b5144e20dec6ab0fa4b9cdaef73a56d3f660aa9788fe97a74567f3eb2b90e1f24595107afa2cfd6e7eeab65b26c819666184717c0cf7fbe304b22d0142053fabd46ddcc5366cac7e9cb9b\u0000",
        "errorMessage":"",
        "status":0
    }
}
```

---

## `getBLSPublicKeyShare`

#### Description
Returns 4 key shares for the specified key name. The BLS key must have been created prior to this call.

#### Request Parameters
| **Parameter** | **Type**   | **Description**                          | **Example value**  |
|---------------|------------|------------------------------------------|--------------|
| `blsKeyName`    | `String`  | [See BLS Key Name](#1-bls-key-name) | `BLS_KEY:SCHAIN_ID:0:NODE_ID:0:DKG_ID:1234`  |

#### Example Request
```bash
curl -X POST --data '{ 
    "jsonrpc": "2.0", 
    "id": 1, 
    "method": "getBLSPublicKeyShare", 
    "params": { 
        "blsKeyName": "BLS_KEY:SCHAIN_ID:0:NODE_ID:0:DKG_ID:1234" 
    } 
}' -H 'content-type:application/json;' -v --key ./sgx.key --cert ./sgx.crt https://127.0.0.1:1026 -k
```

#### Return Values
| **Parameter** | **Type**   | **Description**                          |
|---------------|------------|------------------------------------------|
| `blsPublicKeyShare`   | `String`   | TODO |


#### Example Response

```json
{
    "id":1,
    "jsonrpc":"2.0",
    "result": 
    {
        "blsPublicKeyShare":[
            "8259875648973182338207345628755419732767113596109151631059692327153611502975",
            "1986024687048054068581287577264543712776590334866316595156588738679647059290",
            "13365976864566572809562914579968261802329102141730203169788035381193532073736",
            "17365107436135178485906522781555453387452251547789989556673261886359975878312"
        ],
        "errorMessage":"",
        "status":0
    }
}
```

---

## `blsSignMessageHash`

#### Description
Creates a partial signature using the node's BLS key share

#### Request Parameters
| **Parameter** | **Type**   | **Description**                          | **Example value**  |
|---------------|------------|------------------------------------------|--------------|
| `keyShareName`| `String`   | [See BLS Key Name](#1-bls-key-name)        | `BLS_KEY:SCHAIN_ID:0:NODE_ID:0:DKG_ID:4`  |
| `messageHash` | `String`   | [See Message Hash](#4-message-hash) | `a65b656fd41907d71ea76a`  |
| `n`           |`Unsigned Int`| [See Threshold Encryption parameter n](#5-threshold-encryption-parameters)          | 8            |
| `t`           |`Unsigned Int`| [See Threshold Encryption parameter t](#5-threshold-encryption-parameters)  | 5  |

#### Example Request
```bash
curl -X POST --data '{ 
    "jsonrpc": "2.0", 
    "id": 1, 
    "method": "blsSignMessageHash", 
    "params": { 
        "keyShareName": "BLS_KEY:SCHAIN_ID:0:NODE_ID:0:DKG_ID:4",
        "messageHash": "a65b656fd41907d71ea76a",
        "t": 5,
        "n": 8
    } 
}' -H 'content-type:application/json;' -v --key ./sgx.key --cert ./sgx.crt https://127.0.0.1:1026 -kclear

```

#### Return Values
| **Parameter** | **Type**   | **Description**                          |
|---------------|------------|------------------------------------------|
|`signatureShare`|`String`   | Signature share                          |

#### Example Response

```json
{
    "id":1,
    "jsonrpc":"2.0",
    "result":
    {
        "errorMessage":"",
        "signatureShare":"16837620368415566859682637432908413867102251886281959826579912916726885391430:4084895675643456871268315604525800041504177475018713941166565764320204074532:15272014353970747388859443539029674257510603898285460566131893812841219446314:0",
        "status":0
    }
}
```

---


## `createBLSPrivateKey`

#### Description
-

#### Request Parameters
| **Parameter** | **Type**   | **Description**   | **Example value**  |
|---------------|------------|------------------------------------------|--------------|
| `blsKeyName`| `String`     | [See BLS Key Name](#1-bls-key-name)        | `BLS_KEY:SCHAIN_ID:0:NODE_ID:0:DKG_ID:4` |
| `ethKeyName` | `String`    | [See ECDSA Key Hash](#2-ecdsa-key-name) | `NEK:2dfcf5ff6bcd93fbf45e5589afdf9c9dcff702e9beb5305506967b30a4f2da05`  |
| `secretShare` | `String`     | -         | -  |
| `polyName`    | `String`     | [See Poly Name](#3-poly-name)        | `POLY:SCHAIN_ID:0:NODE_ID:0:DKG_ID:1`  |
| `n`           |`Unsigned Int`| number of nodes in the network         | 8            |
| `t`           |`Unsigned Int`| threshold value - number signature shares that are required to reconstruct the full BLS signature. \(t < n\) | 5  |

#### Example Request
```bash
curl -X POST --data '{ 
    "jsonrpc": "2.0", 
    "id": 1, 
    "method": "blsSignMessageHash", 
    "params": { 
        "blsKeyName": "BLS_KEY:SCHAIN_ID:0:NODE_ID:0:DKG_ID:4",
        "ethKeyName": "NEK:2dfcf5ff6bcd93fbf45e5589afdf9c9dcff702e9beb5305506967b30a4f2da05",
        "secretShare": ,
        "polyName": ,
        "t": 5,
        "n": 8
    } 
}' -H 'content-type:application/json;' -v --key ./sgx.key --cert ./sgx.crt https://127.0.0.1:1026 -k

```

#### Return Values
None

#### Example Response

```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result":
    {
        "errorMessage": "",
        "status":-52
    }
}
```

---


## `popProve`

#### Description
TODO

#### Request Parameters
| **Parameter** | **Type**   | **Description**   | **Example value**  |
|---------------|------------|------------------------------------------|--------------|
| `blsKeyName`| `String`     | [See BLS Key Name](#1-bls-key-name)        | `BLS_KEY:SCHAIN_ID:0:NODE_ID:0:DKG_ID:4` |

#### Example Request
```bash
curl -X POST --data '{ 
    "jsonrpc": "2.0", 
    "id": 1, 
    "method": "popProve", 
    "params": {
        "blsKeyName":"BLS_KEY:SCHAIN_ID:0:NODE_ID:0:DKG_ID:4"
    } 
}' -H 'content-type:application/json;' -v --key ./sgx.key --cert ./sgx.crt https://127.0.0.1:1026 -k
```

#### Return Values
| **Parameter** | **Type**   | **Description**                          |
|---------------|------------|------------------------------------------|
|`popProve`      | `String`  | TODO |

#### Example Response

```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result":
    {
        "errorMessage": "",
        "popProve": "7712004107626570830897885890446468859243922502105843477977107344257047197123:21825471235559662680802288068137317483581335125829352970956762476209081500057:12565777799784373616163068232947461672358328512399717157386114163224678064265:3",
        "status": 0
    }
}
```

---






## `deleteBlsKey`

#### Description
Deletes BLS key from database given the key name.

#### Request Parameters
| **Parameter** | **Type**   | **Description**   | **Example value**  |
|---------------|------------|------------------------------------------|--------------|
| `blsKeyName`| `String`     | [See BLS Key Name](#1-bls-key-name)        | `BLS_KEY:SCHAIN_ID:0:NODE_ID:0:DKG_ID:4` |

#### Example Request
```bash
curl -X POST --data '{ 
    "jsonrpc": "2.0", 
    "id": 1, 
    "method": "deleteBlsKey", 
    "params": {
        "blsKeyName":"BLS_KEY:SCHAIN_ID:0:NODE_ID:0:DKG_ID:4"
    } 
}' -H 'content-type:application/json;' -v --key ./sgx.key --cert ./sgx.crt https://127.0.0.1:1026 -k
```

#### Return Values
| **Parameter** | **Type**   | **Description**                          |
|---------------|------------|------------------------------------------|
|`deleted`      | `boolean`  | `True` if the key was deleted. `False` otherwise.|

#### Example Response

```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result":
    {
        "deleted": true,
        "errorMessage": "",
        "status": 0
    }
}
```

---




# 3) DKG Calls

## `generateDKGPoly`

#### Description
Creates a polynomial of degree `t-1` (where `t` is the threshold parameter) and stores the coefficients (encrypted) in DB under a key with value `polyName`.

The last coefficient (`t-1`) is forced to be non-zero to make sure the polynomial has degree `t-1`.

#### Request Parameters
| **Parameter** | **Type**   | **Description**   | **Example value**  |
|---------------|------------|------------------------------------------|--------------|
| `polyName`    | `String`     | [See Poly Name](#3-poly-name)        | `POLY:SCHAIN_ID:0:NODE_ID:0:DKG_ID:1`  |
| `t`           |`Unsigned Int`| [See Threshold Encryption parameter t](#5-threshold-encryption-parameters). Must be in [1, 32] | 5  |

#### Example Request
```bash
curl -X POST --data '{ 
    "jsonrpc": "2.0", 
    "id": 1, 
    "method": "generateDKGPoly",                    
    "params": {
        "polyName":"POLY:SCHAIN_ID:0:NODE_ID:0:DKG_ID:1", 
        "t": 5
    }                                                               
}' -H 'content-type:application/json;' -v --key ./sgx.key --cert ./sgx.crt https://127.0.0.1:1026 -k

```

#### Return Values
None

#### Example Response

```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result":
    {
        "errorMessage": "",
        "status": 0
    }
}
```

---

## `getVerificationVector`

#### Description
Returns the verification vector for the DKG polynomial identified by `polyName`.

The verification vector contains `t` public G2 points, one for each polynomial coefficient. Each point is returned as an array of 4 decimal strings.

Each point `A_i` is computed as `a_i * G`, where `a_i` is the coefficient `i` and `G` is the generator.

This is the public data later used by `dkgVerification`. 

#### Request Parameters
| **Parameter** | **Type**   | **Description**   | **Example value**  |
|---------------|------------|------------------------------------------|--------------|
| `polyName`    | `String`   | [See Poly Name](#3-poly-name) | `POLY:SCHAIN_ID:0:NODE_ID:0:DKG_ID:1` |
| `t`           | `Unsigned Int` | [See Threshold Encryption parameter t](#5-threshold-encryption-parameters). Must be greater than `0`, and must match the number of coefficients used when the polynomial was generated. | 3 |

#### Example Request
```bash
curl -X POST --data '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "getVerificationVector",
    "params": {
        "polyName":"POLY:SCHAIN_ID:0:NODE_ID:0:DKG_ID:1",
        "t": 3
    }
}' -H 'content-type:application/json;' -v --key ./sgx.key --cert ./sgx.crt https://127.0.0.1:1026 -k

```

#### Return Values
| **Parameter** | **Type**   | **Description**                          |
|---------------|------------|------------------------------------------|
| `verificationVector` | `Array<Array<String>>` | Array of length `t`. Each element is a G2 point encoded as an array of 4 decimal strings: `[x_a, x_b, y_a, y_b]`. |

#### Example Response

```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result":
    {
        "verificationVector": [ // 3 points -> polynomial of degree 2
            [
                "18443897754565973717256850119554731228214108935025491924036055734000366132525",
                "14240403961866329105623123586093845824784504629127034728498768615347524321474",
                "16710466272405633168284855121838772866718811314984330190291911361255661755078",
                "19192291159335672678321340575415025134172782843426265456238300832733199831735"
            ],
            [
                "20322424584479302164643671482890448762900270994752084277213127495531433999909",
                "5931396788532013911711373477132285226477809186754293277406575032002125600559",
                "18359079021653807893652833991146886233057476531311530903272470636638669174041",
                "19466527535508856253705819558467617167997001818319402096497675986097899966464"
            ],
            [
                "11351779463967134282108018417321440499876829582899510386684579733979080274162",
                "2616621985927204507697081602832362990865935003574537491922005166258346735294",
                "16411867714808633216735357212038832380838955637381312556569588324828373582601",
                "3859093521989077157480673057932924349185889732401504031488865259158010973352"
            ]
        ],
        "errorMessage": "",
        "status": 0
    }
}
```

---

## `getSecretShareV2`

#### Description
Computes the V2 encrypted secret shares for all `n` participants using the DKG polynomial identified by `polyName` and the participants' ECDSA public keys.

The response field `secretShare` is one concatenated string containing `n` share records. Each record is exactly 192 hexadecimal characters long and has the following layout:
- 64 hex chars: encrypted secret share payload
- 64 hex chars: ephemeral ECDSA public key X coordinate
- 64 hex chars: ephemeral ECDSA public key Y coordinate

So the total returned string length is always `192 * n` characters.

If the shares for this `polyName` were already computed earlier, the cached value stored in DB may be returned instead of recomputing them.

#### Request Parameters
| **Parameter** | **Type**   | **Description**   | **Example value**  |
|---------------|------------|------------------------------------------|--------------|
| `polyName` | `String` | [See Poly Name](#3-poly-name) | `POLY:SCHAIN_ID:0:NODE_ID:0:DKG_ID:1` |
| `publicKeys` | `Array<String>` | Array of `n` ECDSA public keys, one for each participant. Each key is expected to be a hexadecimal string, typically 128 hex characters long (`X || Y`). | `["bb50e2d89a4ed7...e0e18ef4", "2b7739ccc3e407...9cdebc61"]` |
| `t` | `Unsigned Int` | [See Threshold Encryption parameter t](#5-threshold-encryption-parameters). Must satisfy `1 <= t <= n`. | 3 |
| `n` | `Unsigned Int` | [See Threshold Encryption parameter n](#5-threshold-encryption-parameters). Must satisfy `t <= n <= 32`, and `publicKeys` must contain exactly `n` elements. | 3 |

#### Example Request
```bash
curl -X POST --data '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "getSecretShareV2",
    "params": {
        "polyName": "POLY:SCHAIN_ID:0:NODE_ID:0:DKG_ID:1",
        "publicKeys": [
            "bb50e2d89a4ed70663d080659fe0ad4b9bc3e06c17a227433966cb59ceee020decddbf6e00192011648d13b1c00af770c0c1bb609d4d3a5c98a43772e0e18ef4",
            "2b7739ccc3e407e5cfaf4d04ba05b57efda0cb1ea249c6faf7fd36db3c27fa863d04c2a3b21e8f4911f19b8f91454d7a3afb09da5c58c380685242d09cdebc61",
            "8df45cf98d61606e8143b38df0c0b13f0688abe03614399ad7aef0615213cb0aed18313bd243b1bed3da87768e634d9623b4217910494477aae3c9b9e4199841"
        ],
        "t": 3,
        "n": 3
    }
}' -H 'content-type:application/json;' -v --key ./sgx.key --cert ./sgx.crt https://127.0.0.1:1026 -k

```

#### Return Values
| **Parameter** | **Type**   | **Description**                          |
|---------------|------------|------------------------------------------|
| `secretShare` | `String` | Concatenation of `n` encrypted share records. Each record is 192 hex characters long. To extract participant `i`, take substring `[i * 192, (i + 1) * 192)`. |

#### Example Response

```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result":
    {
        "secretShare": "<share_0_192_hex_chars><share_1_192_hex_chars><share_2_192_hex_chars>",
        "errorMessage": "",
        "status": 0
    }
}
```

---

## `dkgVerification`

#### Description
Verifies that a DKG secret share matches the verification vector derived from the original DKG polynomial, using the ECDSA key identified by `ethKeyName`.

This call does not take `polyName` directly. Instead, it expects:
- `publicShares`: the verification vector already converted into one concatenated hexadecimal string
- `secretShare`: one participant's encrypted secret share, as returned by `getSecretShare`

#### Request Parameters
| **Parameter** | **Type**   | **Description**   | **Example value**  |
|---------------|------------|------------------------------------------|--------------|
| `publicShares` | `String` | Concatenation of `t` public G2 shares. Each share is encoded as 4 hexadecimal components of 64 hex characters each, so total length must be exactly `256 * t` characters. | `28bde30fa0e5...a65a3c74cad` |
| `ethKeyName` | `String` | [See ECDSA Key Name](#2-ecdsa-key-name) | `NEK:2dfcf5ff6bcd93fbf45e5589afdf9c9dcff702e9beb5305506967b30a4f2da05` |
| `secretShare` | `String` | Secret share to verify, encoded as a hexadecimal string of 96 bytes (192 hex characters). This value is one participant slice from the `secretShare` returned by `getSecretShare`. | `53d79fb25ec7c7a19c39145903245a99a8913c3e9e548d433c637b1e74fbbb5b08aca997aa60abd23e7a3c71989ce6e234c28fcdcb3009e7446621b13c05774d9523298e44f460ee2087c093386a30571552dc7d39fb93a0448c3ab954e46ee6` |
| `t` | `Unsigned Int` | [See Threshold Encryption parameter t](#5-threshold-encryption-parameters). Must satisfy `1 <= t <= n`. | 3 |
| `n` | `Unsigned Int` | [See Threshold Encryption parameter n](#5-threshold-encryption-parameters). Must satisfy `t <= n <= 32`. | 3 |
| `index` | `Unsigned Int` | Zero-based participant index of the share being verified. Must be in `[0, n - 1]`. | 0 |

#### Example Request
```bash
curl -X POST --data '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "dkgVerification",
    "params": {
        "publicShares": "28bde30fa0e5a78fab6303c727e77bace3c6e4ab0a8a7c1889c74f3cfe1fa07406926f5a58444d826c001d75e611748d4ede3e6734c15b6d31d0cfcb7525338c2b8de04dfc11ee90b925551b8af98675cfee05c1bfa9ce63b5dbd009e714a164004c7ace3d04017b76ffd14abff4ce4b7d3a08dd49c189bf16c781d3cb1d7bb72eae1988ff79750588eefde7f04ad30203ce77b66219b7ed5aef5a6d52639e300157c32ce3ac6f7ff2a24a590c10d22a1016fa1e851a7d00f6c35a819c2c5a392cb7c43baf36634de008d5088830336a22295e6be9fd6065796f5088294cfc270abe3f18b7aad051204e2a541368be0e1e19084de81f301a3d910d7e89ed50200830a640a1c228334139892f80cf478a0252ab1ae4a770928388bee6fb4668a1144364859926a7ec3e24d4c5efbe2b7c90b592ebb0f1a5541758e4d18e43124c2f0d6421cb8432c08a362e7b76e94fedbb2ad6bb7bd322f8527d71a18cfa1a11232777bfe1bc14a8e248c96f93552d9e48e1ac89c994a928037d0a65a3c74cad",
        "ethKeyName": "NEK:2dfcf5ff6bcd93fbf45e5589afdf9c9dcff702e9beb5305506967b30a4f2da05",
        "secretShare": "53d79fb25ec7c7a19c39145903245a99a8913c3e9e548d433c637b1e74fbbb5b08aca997aa60abd23e7a3c71989ce6e234c28fcdcb3009e7446621b13c05774d9523298e44f460ee2087c093386a30571552dc7d39fb93a0448c3ab954e46ee6",
        "t": 3,
        "n": 3,
        "index": 0
    }
}' -H 'content-type:application/json;' -v --key ./sgx.key --cert ./sgx.crt https://127.0.0.1:1026 -k

```

#### Return Values
| **Parameter** | **Type**   | **Description**                          |
|---------------|------------|------------------------------------------|
| `result` | `boolean` | `true` if the share is valid for the provided verification vector and participant index. `false` otherwise. |

#### Example Response

```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result":
    {
        "errorMessage": "",
        "result": true,
        "status": 0
    }
}
```

---

## `isPolyExists`

#### Description
Checks for existence of polinomial with the name passed as argument.

#### Request Parameters
| **Parameter** | **Type**   | **Description**   | **Example value**  |
|---------------|------------|------------------------------------------|--------------|
| `polyName`    | `String`     | [See Poly Name](#3-poly-name)        | `POLY:SCHAIN_ID:0:NODE_ID:0:DKG_ID:1`  |

#### Example Request
```bash
curl -X POST --data '{
    "jsonrpc": "2.0", 
    "id": 1, 
    "method": "isPolyExists", 
    "params": {
        "polyName":"POLY:SCHAIN_ID:0:NODE_ID:0:DKG_ID:1"
    } 
}' -H 'content-type:application/json;' -v --key ./sgx.key --cert ./sgx.crt https://127.0.0.1:1026 -k

```

#### Return Values
| **Parameter** | **Type**   | **Description**                          |
|---------------|------------|------------------------------------------|
|`IsExist`      | `boolean`  | `True` if key with the passed name exists. `False` otherwise.|

#### Example Response

```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result":
    {
        "IsExist": true,
        "errorMessage": "",
        "status": 0
    }
}
```

---

# 4) Threshold Encryption Calls

## `getDecryptionShares`

#### Description

Decrypts each encoded G2 point sent within the `publicDecryptionValues` array, using the key associated with the name passed by `blsKeyName`. Returns a new array with all the decription shares.

Returns an empty array in case the request has no shares to decrypt.

#### Request Parameters
| **Parameter** | **Type**   | **Description**   | **Example value**  |
|---------------|------------|------------------------------------------|--------------|
| `blsKeyName`    | `String`     | [See BLS Key Name](#1-bls-key-name)  | `BLS_KEY:SCHAIN_ID:8564839...` |
| `publicDecryptionValues`    | `Array<String>`     | Array of elements, where each element represents the U component (G2 point) from the ciphertext, encoded as a [string encoded point](#6-string-encoded-point). The array can be of any size (up to MAX_INT size) | `ABC12345667ADAF...` up to 256 characters (only hexadecimal)  |

#### Example Request
```bash
curl -X POST --data '{ 
    "jsonrpc": "2.0", 
    "id": 1, 
    "method": "getDecryptionShares", 
    "params": {
        "blsKeyName": "BLS_KEY:SCHAIN_ID:85648391426096427994207177239552943688036003763889870037478700400929584288519:NODE_ID:1:DKG_ID:0",
        "publicDecryptionValues": [
            "9f3a7d1cbe84f2a6d5e091b8c74e3a5f9f3a7d1cbe84f2a6d5e091b8c74e3a5f9f3a7d1cbe84f2a6d5e091b8c74e3a5f9f3a7d1cbe84f2a6d5e091b8c74e3a5f9f3a7d1cbe84f2a6d5e091b8c74e3a5f9f3a7d1cbe84f2a6d5e091b8c74e3a5f9f3a7d1cbe84f2a6d5e091b8c74e3a5f9f3a7d1cbe84f2a6d5e091b8c74e3a5f",
            "9f3a7d1cbe84f2a6d5e091b8c74e3a5f9f3a7d1cbe84f2a6d5e091b8c74e3a5f9f3a7d1cbe84f2a6d5e091b8c74e3a5f9f3a7d1cbe84f2a6d5e091b8c74e3a5f9f3a7d1cbe84f2a6d5e091b8c74e3a5f9f3a7d1cbe84f2a6d5e091b8c74e3a5f9f3a7d1cbe84f2a6d5e091b8c74e3a5f9f3a7d1cbe84f2a6d5e091b8c74e3a5f"
        ]
    }
}' -H 'content-type:application/json;' -v --key ./sgx.key --cert ./sgx.crt https://127.0.0.1:1026 -k

```

#### Return Values
| **Parameter** | **Type**   | **Description**                          |
|---------------|------------|------------------------------------------|
|`decryptionShares`      | `Array`  | An array of equal length to the input array sent on the request. Each element corresponds to the decrypted share for the corresponding element from input, and represents a [string encoded point](#6-string-encodeed-point). If decryption of element `i` failed for some reason, this element is set to all `0`s in the `decryptionShares` field of the response, and its index `i` will appear under `failedRequests` |
| `failedRequests`  | `Map` | This field is optional. Only appears if at least one share could not be successfully decrypted. It is a map, where Keys represent the index of the element from `decryptionShares` that failed, and the value will be an `integer` representing the error code.

#### Example Response

```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result":
    {
        "errorMessage": "",
        "status": 0,
        "decryptionShares": [
            "9f3a7d1cbe84f2a6d5e091b8c74e3a5f9f3a7d1cbe84f2a6d5e091b8c74e3a5f9f3a7d1cbe84f2a6d5e091b8c74e3a5f9f3a7d1cbe84f2a6d5e091b8c74e3a5f9f3a7d1cbe84f2a6d5e091b8c74e3a5f9f3a7d1cbe84f2a6d5e091b8c74e3a5f9f3a7d1cbe84f2a6d5e091b8c74e3a5f9f3a7d1cbe84f2a6d5e091b8c74e3a5f",
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        ],
        "failedRequests": {
            "1": 1, // idx 1 has status code 1 -> bad point
        }
    }
}
```




---


# 5) Server Calls


## `getServerStatus`

#### Description
Returns the current server status.

#### Request Parameters
None

#### Example Request
```bash
curl -X POST --data '{ 
    "jsonrpc": "2.0", 
    "id": 1, 
    "method": "getServerStatus", 
    "params": null 
}' -H 'content-type:application/json;' -v --key ./sgx.key --cert ./sgx.crt https://127.0.0.1:1026 -k

```

#### Return Values
| **Parameter** | **Type**   | **Description**                          |
|---------------|------------|------------------------------------------|
|`status`      | `Int`  | `0` if the server is good. If uknown error, the error is `10000 + line number`. |

#### Example Response

```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result":
    {
        "errorMessage": "",
        "status": 0
    }
}
```

---


## `getServerVersion`

#### Description
Returns the current SgxWallet server version.

#### Request Parameters
None

#### Example Request
```bash
curl -X POST --data '{ 
    "jsonrpc": "2.0", 
    "id": 1, 
    "method": "getServerVersion", 
    "params": null 
}' -H 'content-type:application/json;' -v --key ./sgx.key --cert ./sgx.crt https://127.0.0.1:1026 -k

```

#### Return Values
| **Parameter** | **Type**   | **Description**                          |
|---------------|------------|------------------------------------------|
|`version`      | `Int`  | `0` if the server is good. If uknown error, the error is `10000 + line number`. |

#### Example Response

```json
{
    "id": 1,
    "jsonrpc": "2.0",
    "result":
    {
        "errorMessage": "",
        "status": 0,
        "version": "1.9.0"
    }
}
```

---



# Common Parameters Descriptions

#### 1) BLS Key Name
- **Type**: String  
- **Description**: Unique identifier for the key share. This is the value used to get the respective key value. Must follow a specific format: `BLS_KEY:SCHAIN_ID:<schain_id>:NODE_ID:<node_id>:DKG_ID:<dkg_id>`
    - `schain_id`: Identifier for the shard chain. Must not exceed 78 characters long.
    - `node_id`: Identifier for the node.
    - `dkg_id`: Identifier for the distributed key generation process. Must not exceed 78 characters long.

#### 2) ECDSA Key Name
- **Type**: String  
- **Description**: Unique identifier for the ECDSA key. This is the value used to get the respective key value. Must follow a specific format: `NEK:<key-id>`:
  - `key_id`: Any unique id for the key (TODO - CHECK THIS)

#### 3) Poly Name
- **Type**: String  
- **Description**: Unique identifier for a DKG polinomial. Must follow a specific format: `POLY:SCHAIN_ID:0:NODE_ID:0:DKG_ID:1`
  - [See 1) - BLS Key Name description of each of the fields](#1-bls-key-name)


#### 4) Message Hash
- **Type**: String
- **Description**: Hash of any value in hexadecimal format. May be prefixed with `0x` or `0X`.
  - Example: `0x1b427aa872c` or `c33a97ff`


#### 5) Threshold Encryption Parameters
`n` - Number of total nodes participating in the threshold encryption network.  
`t` - The **threshold value**. At least `t` participants must collaborate to reconstruct the secret or perform operations (e.g., signing). Requirement: \(t < n\).


#### 6) String encoded point
- **Type**: String
- **Description**: 256-hexadecimal character representing a point in elliptic curve
