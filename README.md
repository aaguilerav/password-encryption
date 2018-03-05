# Secure Password Storage
---
[![Build Status](https://travis-ci.org/aaguilerav/password-encryption.svg?branch=master)](https://travis-ci.org/aaguilerav/password-encryption)

## <a id="index"></a>Index

* [**Description.**](#description)
* [**Pre-requisites.**](#preRequisites)
* [**Configuration.**](#configuration)
* [**Packaging.**](#packaging)
* [**Deployment.**](#deployment)
* [**List of Services.**](#listOfServices)
* [**Changelog.**](#changelog)
* [**Additional Resources.**](#additionalResources)

## <a id="description"/></a>Description
Component used for symmetric encryption and secure hash generation ([scrypt key derivation function](http://www.tarsnap.com/scrypt.html)) for secure password storage.

[Back to Index ^](#index)

## <a id="preRequisites"/></a>Pre-requisites
For this component to work properly, some pre-requisites are needed:
* Java 7.
* [Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files.](http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html)
* [`scrypt`](http://www.tarsnap.com/scrypt.html) at OS level. For mac users, use `brew install scrypt`.

[Back to Index ^](#index)

## <a id="configuration"/></a>Configuration
No configuration needed.

[Back to Index ^](#index)

## <a id="packaging"/></a>Packaging
In order to compile and package this component in it's JAR form, [maven 3.0](https://maven.apache.org/) or above is needed, just type the command `mvn clean package` where the `pom.xml` file is, and the `password-encryption-x.x.x.jar` file will be created at `password-encryption/target`.

[Back to Index ^](#index)

## <a id="deployment"/></a>Deployment
This component is deployed as a dependency for other projects.

[Back to Index ^](#index)

## <a id="listOfServices"></a>List of Services
No services exposed as APIs.

[Back to Index ^](#index)

## <a id="changelog"/></a>Changelog
| VERSION       | DESCRIPTION  |
|:-------------:|:-------------|
| 1.0.0         | First version of the component. |

[Back to Index ^](#index)

## <a id="additionalResources"/></a>Additional Resources

* [scrypt key derivation function](http://www.tarsnap.com/scrypt.html)
* [Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files.](http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html)
* [Apache Maven](https://maven.apache.org/)
* [NIST Recommendation for Block 2001 Edition Cipher Modes of Operation: Methods and Techniques ](http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)
* [NIST Recommendation for Block Cipher Modes of Operation: Methods for Format-Preserving Encryption](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf)

[Back to Index ^](#index)
