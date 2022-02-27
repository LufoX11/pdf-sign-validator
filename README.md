# PDF Sign Validator

PDF Sign Validator is a simple wrapper to validate a PDF signature against a public key.\
After spending an entire day looking for a similar solution I gave up and ended up building a solution by myself with the help of my best friend, John Stack Overflow.\
This is nothing more than just a wrapper of real cryptographic functions from [Sop\ANS1](https://github.com/sop/asn1) and [Sop\X509](https://github.com/sop/x509) repositories.

## Installation

Just require this package in your project using Composer:

```bash
composer require lufox11/pdf-sign-validator
```

## Usage

Methods you may'd like to use:

**signCount**: Returns the amount of signatures found in file.\
**signIsValid**: Validates that the file signature corresponds to the issuer's root PEM certificate.\
**certIsValid**: Validates that the subject certificate was issued by the issuer certificate.\
**signMatchSubject**: Validates that the certificate (extracted from the signature) match the subject's PEM certificate.\
**infoFromPDF**: Reads an attached signature to a PDF file and returns the info inside.\
**infoFromPEM**: Reads a certificate in PEM format and returns the info inside.

A real use case (Argentina):

1. Sign a PDF file through [Firmar.gob.ar](https://firmar.gob.ar/firmador/#/) and download the file (`signed.pdf`).
2. [Download](https://www.acraiz.gob.ar/Content/Archivos/certificados/licenciados_acraiz2016/01.crt) the issuer's root certificate (`issuer.cer`).
3. [Download](https://firmar.gob.ar/RA/system/home#/certificados) your public certificate (`subject.cer`).

```php
use LufoX11\PdfSignValidator\PdfSignValidator;

/**
 * signed.pdf: Path to the signed PDF file.
 * issuer.cer: Path to the public key file (RSA PUBLIC KEY) of the issuer.
 * subject.cer: Path to the public key file (RSA PUBLIC KEY) of the subject.
 */

$amountOfSignatures = PdfSignValidator::signCount('signed.pdf');
$certificateIsValid = PdfSignValidator::certIsValid('subject.cer', 'issuer.cer');
$certificateData = PdfSignValidator::infoFromPEM('certificate.cer');
$certificateData = PdfSignValidator::infoFromPDF('signed.pdf');

// Single signature in PDF file
$signatureIsValid = PdfSignValidator::signIsValid('signed.pdf', 'issuer.cer');
$certificateMatchSubject = PdfSignValidator::signMatchSubject('signed.pdf', 'subject.cer');

// Multiple signatures in PDF file
// You can specify the signature to work with in dot notation
$signatureIsValid = PdfSignValidator::signIsValid('signed.pdf', 'issuer.cer', [ 'subject.common_name' => 'Lionel Messi' ]);
$certificateMatchSubject = PdfSignValidator::signMatchSubject('signed.pdf', 'subject.cer', [ 'issuer.common_name' => 'Magnus Carlsen' ]);
```

## License
This project is licensed under the [MIT License](https://choosealicense.com/licenses/mit/).
