<?php

namespace LufoX11\PdfSignValidator;

use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Element;
use Sop\X509\Certificate\Certificate;
use Sop\X509\Certificate\TBSCertificate;
use Sop\CryptoEncoding\PEM;
use BinaryCube\DotArray\DotArray;

abstract class PdfSignValidator
{
    const SIGN_REGEX = '/ByteRange\s*\[(\d+) (\d+) (\d+) (\d+)?/';

    /**
     * Returns the amount of signatures found in file.
     *
     * @param string $filePath Path to the PDF file.
     * @return int
     */
    public static function signCount($filePath): int
    {
        self::mustBeReadable($filePath);
        $res = 0;
        if (preg_match_all(self::SIGN_REGEX, file_get_contents($filePath), $matches)) {
            $res = count($matches[0]);
        }

        return $res;
    }

    /**
     * Reads an attached signature to a PDF file and returns the info inside.
     *
     * @param string $filePath Path to the PDF file.
     * @return array
     */
    public static function infoFromPDF($filePath): array
    {
        self::mustBeReadable($filePath);
        $res = [];
        if ($signatures = self::pdf2pkcs7($filePath)) {
            foreach ($signatures as $s) {
                $res[] = self::infoFromPKCS7($s);
            }
        }

        return $res;
    }

    /**
     * Reads a certificate in PEM format and returns the info inside.
     * Note: The PEM file MUST be of type "RSA PUBLIC KEY".
     *
     * @param string $filePath Path to the certificate file in PEM format.
     * @return array
     */
    public static function infoFromPEM($filePath): array
    {
        self::mustBeReadable($filePath);
        $pem = PEM::fromFile($filePath);
        $cert = Certificate::fromPEM($pem);
        $res = self::formatCertificate($cert);

        return $res;
    }

    /**
     * Validates that the file signature corresponds to the issuer's root PEM certificate.
     *
     * Note: If multiple signatures are found you can specify which one you want to validate through
     * $which param, otherwise the last one will be evaluated. If there is more than one match, only
     * the first will be considered.
     *
     * @param string $pdf Path to the signed PDF file.
     * @param string $pem Path to the issuer's PEM file.
     * @param array $which Dot notation of the key and value of the signature we want to validate.
     *                     Eg: [ 'subject.common_name' => 'Lionel Messi' ]
     * @return bool
     */
    public static function signIsValid($pdf, $pem, array $which = null): bool
    {
        $res = false;
        $pdfCert = self::infoFromPDF($pdf);
        $pemCert = self::infoFromPEM($pem);

        if ($which) {
            if ($pdfCert = DotArray::create($pdfCert)->find(
                fn ($v) => DotArray::create($v)->get(key($which)) == current($which)
            )) {
                $pdfCert = $pdfCert->toArray();
            }
        } else {
            $pdfCert = end($pdfCert);
        }

        if ($pdfCert) {
            $res = $pdfCert['cert']->verify($pemCert['cert']->tbsCertificate()->subjectPublicKeyInfo());
        }

        return $res;
    }

    /**
     * Validates that the subject certificate was issued by the issuer certificate.
     *
     * @param string $subjectPem Path to the subject's PEM file.
     * @param string $issuerPem Path to the issuer's PEM file.
     * @return bool
     */
    public static function certIsValid($subjectPem, $issuerPem): bool
    {
        $subjectCert = self::infoFromPEM($subjectPem)['cert'];
        $issuerCert = self::infoFromPEM($issuerPem)['cert'];
        $res = $subjectCert->verify($issuerCert->tbsCertificate()->subjectPublicKeyInfo());

        return $res;
    }

    /**
     * Validates that the certificate (extracted from the signature) match the subject's PEM certificate.
     *
     * Note: If multiple signatures are found you can specify which one you want to match through
     * $which param, otherwise the last one will be evaluated. If there is more than one match, only
     * the first will be considered.
     *
     * @param string $pdf Path to the signed PDF file.
     * @param string $pem Path to the subject's PEM file.
     * @param array $which Dot notation of the key and value of the signature we want to match.
     *                     Eg: [ 'subject.common_name' => 'Lionel Messi' ]
     * @return bool
     */
    public static function signMatchSubject($pdf, $pem, array $which = null): bool
    {
        $res = false;
        $pdfCert = self::infoFromPDF($pdf);
        $pemCert = self::infoFromPEM($pem);

        if ($which) {
            if ($pdfCert = DotArray::create($pdfCert)->find(
                fn ($v) => DotArray::create($v)->get(key($which)) == current($which)
            )) {
                $pdfCert = $pdfCert->toArray();
            }
        } else {
            $pdfCert = end($pdfCert);
        }

        if ($pdfCert) {
            $res = $pdfCert['cert']->equals($pemCert['cert']);
        }

        return $res;
    }

    /**
     * Returns a formatted (and readable) certificate.
     *
     * @param Sop\X509\Certificate\Certificate $cert
     * @return array
     */
    protected static function formatCertificate(Certificate $cert): array
    {
        $res = [];
        $subject = $cert->tbsCertificate()->subject();
        $issuer = $cert->tbsCertificate()->issuer();
        $validity = $cert->tbsCertificate()->validity();
        try { $res['subject']['common_name'] = (string) $subject->firstValueOf('commonName'); } catch (\Exception $e) {}
        try { $res['subject']['owner'] = (string) $subject->firstValueOf('o'); } catch (\Exception $e) {}
        try { $res['subject']['serial_number'] = (string) $subject->firstValueOf('serialNumber'); } catch (\Exception $e) {}
        try { $res['subject']['country'] = (string) $subject->firstValueOf('c'); } catch (\Exception $e) {}
        try { $res['issuer']['owner'] = (string) $issuer->firstValueOf('o'); } catch (\Exception $e) {}
        try { $res['issuer']['common_name'] = (string) $issuer->firstValueOf('commonName'); } catch (\Exception $e) {}
        try { $res['issuer']['serial_number'] = (string) $issuer->firstValueOf('serialNumber'); } catch (\Exception $e) {}
        try { $res['issuer']['country'] = (string) $issuer->firstValueOf('c'); } catch (\Exception $e) {}
        try { $res['validity']['from'] = $validity->notBefore()->dateTime(); } catch (\Exception $e) {}
        try { $res['validity']['to'] = $validity->notAfter()->dateTime(); } catch (\Exception $e) {}
        try { $res['public_key'] = $cert->tbsCertificate()->subjectPublicKeyInfo()->publicKey(); } catch (\Exception $e) {}
        try { $res['signature'] = bin2hex($cert->signatureValue()->bitString()); } catch (\Exception $e) {}
        $res['cert'] = $cert;

        return $res;
    }

    /**
     * Returns the attached signature(s) from a PDF file in PKCS7 format (binary).
     *
     * @param string $filePath Path to the PDF file.
     * @return array
     */
    protected static function pdf2pkcs7($filePath): array
    {
        self::mustBeReadable($filePath);
        $res = [];
        preg_match_all(self::SIGN_REGEX, file_get_contents($filePath), $bytes);
        if ($bytes[2][0] ?? $bytes[3][0] ?? false) {

            // In case more than one signature is found
            for ($i = 0; $i < count($bytes[2]); $i++) {
                $start = $bytes[2][$i];
                $end = $bytes[3][$i];
                $stream = fopen($filePath, 'rb');
                $res[] = hex2bin(stream_get_contents($stream, $end - $start - 2, $start + 1));
                fclose($stream);
            }
        }

        return $res;
    }

    /**
     * Reads a certificate in PKCS7 format (binary) and returns the info inside.
     *
     * @param string $binaryData
     * @return array
     */
    protected static function infoFromPKCS7($binaryData): array
    {
        $seq = Sequence::fromDER($binaryData);
        $signedData = $seq->getTagged(0)->asExplicit()->asSequence();
        $ecac = $signedData->getTagged(0)->asImplicit(Element::TYPE_SET)->asSet();
        $ecoc = $ecac->at($ecac->count() - 1);
        $cert = Certificate::fromASN1($ecoc->asSequence());
        $res = self::formatCertificate($cert);

        return $res;
    }

    /**
     * Through a new exception if the passed file is not readable.
     *
     * @param string $file File path.
     * @return void
     */
    private static function mustBeReadable($file): void
    {
        if (!is_readable($file)) {
            throw new \Exception("Couldn't open file {$file}.");
        }
    }
}
