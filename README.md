# Encoding Helper

It is a small tool to convert encoding, which I wrote long long time ago.

It's useful to me and someone may need it too, so I extract it from old code repo and build it to a standalone tool.

## Functions

### Conversion

* 10-16 number conversion
* 10-2 number conversion

* Base64 encode/decode
* Hex-Ascii encode/decode
* Hex-Base64 encode/decode
* HTML escape/unescape
* SQL escape/unescape
* Timstamp-String conversion
* NativeString-AsciiString conversion
* URL encode/decode
* XML_parameter-Base64 encode/decode
* Zip-Base64 encode/decode
* Zip-Base64-with-len encode/decode

### Checksum
* CRC32 calculation
* MD2 hash
* MD5 hash
* SHA1 hash
* SHA2 hash

## Generation
* UUID generation
* Random string generation

## Encryption

* AES encryption/decryption

    - mode:
        - CBC
        - CFB
        - ECB
        - OFB

    - padding:
        - NoPadding
        - PKCS5Padding
        - ISO10126Padding
        - SSL3Padding


![snapshot](snapshot.png)

Please star it if you like it :)

You can raise issue to me if you want new functions.

Thanks,
Walter

## How to use it?

1. clone this repo

   ensure you installed jdk and maven

2. cd encoding_helper

3. compile and package, JDK is required

```sh
mvn package
```

4. run it

```sh
# windows
./target/encoding_helper.exe
# linux or macos
./target/encoding_helper
```

## Reference

### AES algorithm

| # | Name | Description | Padding | Comments|
|---|---|---|---|---|
| 1 | ECB (Electronic Code Book) |  The plaintext is divided into blocks with a size of 128 bits. Then each block is encrypted with the same key and algorithm. | need | 数据被分成128位的块，每个块使用相同的密钥独立加密。如果两个块的数据相同，加密后的结果也会相同，这可能导致安全漏洞 |
| 2 | CBC (Cipher Block Chaining) | CBC mode uses an Initialization Vector (IV) to augment the encryption. First, CBC uses the plaintext block xor with the IV. Then it encrypts the result to the ciphertext block. In the next block, it uses the encryption result to xor with the plaintext block until the last block. | need | 密码链接模式, 每个块的加密依赖于前一个块的加密结果，引入了初始向量（IV）来保证不同块的加密结果不同 |
| 3 | CFB (Cipher FeedBack) | First, it encrypts the IV, then it will xor with the plaintext block to get ciphertext. Then CFB encrypts the encryption result to xor the plaintext. It needs an IV. | need | |
| 4 | OFB (Output FeedBack) | OFB mode uses an Initialization Vector (IV) to augment the encryption. First, OFB uses the plaintext block xor with the IV. Then it encrypts the result to the ciphertext block. In the next block, it uses the encryption result to xor with the plaintext block until the last block. | need | 输出反馈模式，类似于CTR模式，但是加密过程是反馈到下一个块的加密中。可以处理任意长度的数据，但通常不如CTR模式高效。|
| 5 |CTR (Counter) | This mode uses the value of a counter as an IV. It’s very similar to OFB, but it uses the counter to be encrypted every time instead of the IV. This mode has two strengths, including encryption/decryption parallelization, and noise in one block does not affect other blocks. | need not | 计数器模式, 将AES变为流密码。不需要填充，可以加密任意长度的数据。使用一个递增的计数器来保证每个块的加密结果不同 |
| 6 | GCM (Galois/Counter Mode) | This mode is an extension of the CTR mode. The GCM has received significant attention and is recommended by NIST. The GCM model outputs ciphertext and an authentication tag. The main advantage of this mode, compared to other operation modes of the algorithm, is its efficiency. | need not | 伽罗瓦/计数器模式，Galois/Counter Mode）：结合了CTR模式和认证加密。除了加密数据，还可以提供数据完整性和认证。需要一个唯一的初始化向量（IV）和认证标签 |

