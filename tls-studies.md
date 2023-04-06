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
A digital signature is when for example the sender creates two hash values, one is encrypted with its private key and sends it to the receiver. The receiver who then has access to the senders public key can decrypt the encrypted hash and can compare the two values are the same, thus conforming the senders identity and integrity.
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
Expired / Misconfigured certificates, Self-signed, Phishing Sites using https, CA attacks, Certificate expiration and no rotation..

POODLE = Padding Oracle On Downgraded Legacy Encryption.
The client initiates the handshake and sends a list of supported SSL/TLS versions. An attacker intercepts the traffic, performing a man-in-the-middle (MITM) attack, and impersonates the server until the client agrees to downgrade the connection to SSL 3.0. Then using automated tools the attacker kan decipher data exploiting the SSL 3.0 protocol.

## • Describe how phishing websites work 
Tricking users into disclosing private information by using a website that looks similar to the original website.

## • Describe Server Name Indication (SNI) 
TLS does not provide a mechanism for a client to tell the server the name of the website it is trying to contact. It is desirable to provide this information when a server is hosting multiple websites

## • Describe Certificate Transparency (CT)
Certificate Transparency (CT) is a mechanism for publicly logging all SSL/TLS certificates issued by Certificate Authorities (CAs) in a way that makes it possible to detect and respond to fraudulent or malicious certificates. In a typical CT system, the CA is required to submit each SSL/TLS certificate it issues to one or more publicly accessible logs. These logs then make the certificates available for public inspection, allowing anyone to monitor the issuance of SSL/TLS certificates and to detect any suspicious or fraudulent activity.

## • Describe Certificate Authority Authorisation (CAA)
Certificate Authority Authorization (CAA) is a DNS security standard that enables domain name owners to specify which Certificate Authorities (CAs) are authorized to issue SSL/TLS certificates for their domain. This mechanism is designed to prevent fraudulent or unauthorized issuance of SSL/TLS certificates by a rogue or compromised CA.

## • Describe Certificate Pinning
Certificate Pinning is a security technique used to prevent man-in-the-middle (MITM) attacks by ensuring that a web or mobile application only accepts SSL/TLS certificates from a specific set of trusted Certificate Authorities (CAs) or public key hashes.

In certificate pinning, the client application includes a predefined set of one or more public key hashes or X.509 certificate details that are associated with the server's SSL/TLS certificate. When the client connects to the server, it verifies that the presented SSL/TLS certificate matches the predefined set of details or hashes. If it doesn't match, the connection is terminated.

There are two types of certificate pinning: Static and Dynamic.

Static Pinning involves hardcoding a specific set of SSL/TLS certificate details or public key hashes within the application's codebase. This is inflexible and requires manual updating if the SSL/TLS certificate changes.

Dynamic Pinning involves specifying a set of SSL/TLS certificate details or public key hashes in the application's code, but also allows for the inclusion of additional SSL/TLS certificates that are not specified in the code. This is more flexible and allows for automatic updating of SSL/TLS certificates.

## • Describe HTTP Strict Transport Security (HSTS)
HTTP Strict Transport Security (HSTS) is a security mechanism that allows web servers to instruct user agents (such as web browsers) to only communicate with them using secure HTTPS connections, and to automatically upgrade insecure HTTP connections to HTTPS. HSTS helps to protect against various types of attacks that exploit weaknesses in the HTTP protocol, such as man-in-the-middle attacks, SSL stripping, and cookie hijacking.

## • Describe HTTP/2
HTTP/2 (or simply HTTP2) is a major revision of the HTTP (Hypertext Transfer Protocol) network protocol that is used to transfer data between web servers and clients (such as web browsers). HTTP2 was designed to address the limitations and performance issues of HTTP/1.x, and to provide a faster, more efficient, and more secure web browsing experience.

### Some of the key features and improvements of HTTP2 are:
Multiplexed streams: HTTP2 allows multiple requests and responses to be sent and received simultaneously over a single TCP connection, which reduces the latency and improves the performance of web pages.

#### Binary protocol: 
HTTP2 uses a binary protocol instead of the text-based protocol of HTTP/1.x, which makes it more efficient to parse and process, and reduces the overhead of data transmission.

#### Server push: 
HTTP2 allows servers to push resources (such as images, scripts, and stylesheets) to the client's cache before they are requested, which can reduce the number of round trips required to load a web page and improve the performance.

#### Header compression: 
HTTP2 uses a new header compression algorithm (HPACK) that reduces the size of header fields, which reduces the amount of data that needs to be transmitted and improves the performance.

# Secure by default: 
## • Explain the term “Always-on SSL”
HTTP2 requires the use of TLS (Transport Layer Security) encryption by default, which provides greater security and privacy for web browsing.
## • Explain the role of the CA/B Forum
## • List and describe best practices for SSL security and performance