# TLS Studies
## Describe the main purpose and functions of SSL & TLS
Secure communication across a network, like web-traffic from HTTP to HTTPS or other applications like mail or VPN.
## • Describe the history and versions of SSL & TLS
SSL v2.0-v.3.0 from 1995-1996. TLS is an updated version of SSL versions v1.0, v1.1, v1.2, v.1.3.
## • Describe symmetric and asymmetric encryption models
### Symmetric (Secret Key):
Same key used for encryption and decryption. Both parties have the same key.
### Asymmetric (Public Key Infrastructure) PKI 
Both parties have a private and public key. The public keys are exchanged and traffic meant for the other party is encrypted with the other party's public key. The private key of the receiving party is then used to decrypt the message.
## • Describe how digital signatures work
A digital signature is when for example the sender creates two hash values, one is encrypted with its private key and sends it to the receiver. The receiver who then has access to the senders public key can decrypt the encrypted has and can compare the two values are the same, thus conforming the senders identity and integrity.
## • Describe the details of an SSL/TLS certificate, including extensions and file formats
SSL/TLS certificate is used to secure communication between a client and a server. It contains information about the websites domain name, owner and certificate validity period, public key, signature algorithm used by the CA.
### Extensions
Additional pieces of information that can be included in the certificate.
CA key identifier, SAN (Server Alternative Names), Certificates intended usage.
### Formats
PEM (Privacy-Enhanced Mail) =  Base64-encoded, stores certificate in plain text.
DER (Distinguished Encoding Rule) = Binary format.
PFX / PKCS#12 = Binary format, includes both certificate and the private key.
P7B/ PKCS#7 = Binary format, includes only the certificate chain (certificate + intermediates ) used to install SSL / TLS on a server. Private key is usually kept separate.
## • Describe DV, OV, EV and private SSL certificates
DV = Domain Validation, OV = Organization Validation, EV = Extended Validation. Private SSL Certificates = Self Signed (NO CA).
Validation:
• Common Name (CN) - the fully qualified domain name such as www.digicert.com
• Organization (O) - legal company name
• Organizational Unit (OU) - division or department of company
• Locality or City (L) e.g. London
• State or Province (S) - must be spelled out completely such as New York or California
• Country Name (C) - 2-character country code such as US
## • Describe the benefits of EV certificates
EV = Highest Level of security, provides green address bar in some browsers, and display the name of the organization that own the domain. Overall provides additional level of security.
The above + the below is validated:
• Company Street Address
• Postal Code
• Business Category
• Serial Number (Business Registration Number)
• Jurisdiction State
• Jurisdiction Locality
## • Describe SAN and wildcard certificates
SAN  = Subject Alternative Name, used to protect multiple websites with the same certificate.
Wildcard = For example *.asd.com. Used to protect multiple subdomains. Not allowed for Extended Validation.
## • Describe domain control and organization validation methods
### Domain Control: Owner need to prove control over domain.

### Organization Validation Methods:
Document Verification: Prove ownership with legal document that verifies owner of the organization.
Phone Verification: The CA calls phone number associated with the company.
Third-party database verification.
Site visit.

## • Describe how the SSL/TLS “handshake” works in detail, Including the role of root, intermediate (ICA), end-entity and cross-root certificates.

RSA and DHE (Diffie-Hellman Ephemeral) are key exchange algorithms used in the TLS handshake. The RSA key exchange algorithm is used in TLS 1.0 and TLS 1.1, while the DHE algorithm is used in TLS 1.2 and later versions.

The key difference between RSA and DHE is the way they exchange keys. In RSA, the client generates a random number and encrypts it using the server's public key. The server decrypts the message using its private key and generates the symmetric key for the session. 

In DHE, the client and server exchange public keys and use them to generate a shared secret. This shared secret is then used to generate the symmetric key for the session.

### Intermediate CA
 links together leaf certificates to root CA creating a chain to the CA. This is because it is a security risk for the root CA to issue leaf certificates directly.

### TLS/SSL 1.0 - RSA
#### Handshake 
##### 1 - Client Hello
Random String + List of Cipher Suites.
##### 2 - Server Hello
Asserts its identity by providing its certificate. And chooses the strongest cipher suite that both client and server support.
##### 3 - Client Master Key 
Client first verifies signature of the certificates Certificate Authority (CA) (root). To the public key of the CA embedded in the client application. After verifying the server the client generates a "Master Session Key". This key is used as a seed to to generate the server and client keys.
##### 4 - Server Verify
Server decrypts the master session key using the servers private key and using the session key to create the corresponding server key pairs.

### TLS 1.2 DHA (Diffie-Hellman Ephemeral)

### TLS 1.3 DH (Diffie Hellman)

## • Describe the CRL and OCSP methods for revocation checking (including OCSP Stapling)
CRL = Certificate Revocation list
OCSP = Online Certificate Status Protocol 

Two methods for checking revocation status.

CRL = Publishes a list of revoked certificates on a public list.
OCSP = Client sends a request to OCSP server with the certificates serial number.

OCSP Stapling = Technique that improves performance and privacy of OCSP checks.

## • List common algorithms used in TLS for key agreement, encryption, digital signatures, and hashing
Key Exchange - RSA, DH, ECDH, PSK
Authentication (Signature) - RSA, DSA
Bulk Encryption (Encrypt Data beeing sent) - AES, Cameilla, ARIA
Message Authentication Code - SHA-256

All these make up a "Cipher Suite" Ex:
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

• TLS is the protocol.
• ECDHE is the key exchange algorithm ephemeral Elliptic Curve Diffie Hellman (ECDHE).
• RSA is the authentication (signature) algorithm.
• AES_128_GCM is the bulk encryption algorithm.
• SHA-256 is the MAC algorithm.


## • Describe “Forward Secrecy”
Fear that data can be decrypted in the future if key was disclosed. "Forward Secrecy" is obtained by generating new key material for each session.

## • List the benefits of Elliptic Curve
Stronger Encryption
Performance
Scalable


## Cryptography for TLS
## • Explain the dangers of expired, misconfigured, self-signed and “vendor” certificates
- Expired certificates can lead to trust errors in the browser, which in turn discourage users to visit the site.
- Webpage outage.
- Make client vulnerable to "MITM" attacks.
- Self-signed: No third party to verify the validity of the certificate.


## • Identify common vulnerabilities of outdated protocols (Heartbleed, etc) 
## • Describe how phishing websites work 
## • Describe Server Name Indication (SNI) 

## • Describe Certificate Transparency (CT) • Describe Certificate Authority
##   Authorisation (CAA)
## • Describe Certificate Pinning
## • Describe HTTP Strict Transport Security (HSTS)
## • Describe HTTP/2
## • Explain the term “Always-on SSL”
## • Explain the role of the CA/B Forum
## • List and describe best practices for SSL
## security and performance