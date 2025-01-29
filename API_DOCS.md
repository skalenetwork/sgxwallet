# API RPC Methods Specification

> ---
> ## Table of Contents
> ##### 1) ECDSA calls
>   1. [generateECDSAKey](#generateecdsakey) (TODO - complete)
>   2. [importECDSAKey](#importecdsakey) (TODO - complete & test)
>   3. [getPublicECDSAKey](#getpublicecdsakey)
>   4. [ecdsaSignMessageHash](#ecdsaSignMessageHash)
> ##### 2) BLS calls
>   1. [importBLSKeyShare](#importblskeyshare)
>   2. [getBLSPublicKeyShare](#getblspublickeyshare) (TODO - complete description)
>   3. [blsSignMessageHash](#blssignmessagehash)
>   4. [createBLSPrivateKey](#createblsprivatekey) (TODO - complete & test)
>   4. [deleteBlsKey](#deleteblskey)
> ##### 3) DKG calls
>   1. [generateDKGPoly](#generatedkgpoly) 
>   2. [isPolyExists](#ispolyexists) 
> ##### [4) Common Parameter Descriptions](#common-parameters-descriptions)
> ---


> TODO calls
> - getSecretShare
> - getSecretShareV2
> - dkgVerification
> - dkgVerificationV2
> - calculateAllBLSPublicKeys
> - complaintResponse
> - multG2
> - getServerStatus
> - getServerVersion
> - generateBLSPrivateKey
> - createBLSPrivateKeyV2
> - getDecryptionShares
> - popProve

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
| `keyName`     | `String`   | [See ECDSA Key Name](#2-ecdsa-ley-name)    |
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
}' -H 'content-type:application/json;' -v --key ./sgx.key --cert ./sgx.crt https://127.0.0.1:1026 -kclear
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
Creates a polynomial of degree `t-1` (where `t` is the threshold parameter).

#### Request Parameters
| **Parameter** | **Type**   | **Description**   | **Example value**  |
|---------------|------------|------------------------------------------|--------------|
| `polyName`    | `String`     | [See Poly Name](#3-poly-name)        | `POLY:SCHAIN_ID:0:NODE_ID:0:DKG_ID:1`  |
| `t`           |`Unsigned Int`| [See Threshold Encryption parameter t](#5-threshold-encryption-parameters) | 5  |

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