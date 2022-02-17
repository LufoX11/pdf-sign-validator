<?php

namespace LufoX11\PdfSignValidator;

use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Element;
use Sop\X509\Certificate\Certificate;
use Sop\X509\Certificate\TBSCertificate;
use Sop\CryptoEncoding\PEM;

abstract class PdfSignValidator
{
    /**
     * Reads an attached certificate to a PDF file and returns the info inside.
     *
     * @param string $filePath Path to the PDF file.
     * @return array
     */
    public static function infoFromPDF($filePath): array
    {
        $pkcs7 = self::pdf2pkcs7($filePath);
        $res = self::infoFromPKCS7($pkcs7);

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
        $res = [];
        if (is_readable($filePath)) {
            $pem = PEM::fromFile($filePath);
            $cert = Certificate::fromPEM($pem);
            $res = self::formatCertificate($cert);
        } else {
            throw new \Exception("Couldn't open file {$filePath}.");
        }

        return $res;
    }

    /**
     * Validates that the file signature corresponds to the issuer's root PEM certificate.
     *
     * @param string $pdf Path to the signed PDF file.
     * @param string $pem Path to the issuer's PEM file.
     * @return bool
     */
    public static function signIsValid($pdf, $pem): bool
    {
        $pdfCert = self::infoFromPDF($pdf);
        $pemCert = self::infoFromPEM($pem);
        $res = $pdfCert['cert']->verify($pemCert['cert']->tbsCertificate()->subjectPublicKeyInfo());
        #$res = ($pdfCert['signature'] == $pemCert['signature']);

        return $res;
    }

    /**
     * Validates that the file certificate (extracted from signature) match the subject's PEM certificate.
     *
     * @param string $pdf Path to the signed PDF file.
     * @param string $pem Path to the subject's PEM file.
     * @return bool
     */
    public static function certIsValid($pdf, $pem): bool
    {
        $pdfCert = self::infoFromPDF($pdf);
        $pemCert = self::infoFromPEM($pem);
        $res = $pdfCert['cert']->equals($pemCert['cert']);

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
     * Returns the attached certificate from a PDF file in PKCS7 format (binary).
     *
     * @param string $filePath Path to the PDF file.
     * @return mixed
     */
    protected static function pdf2pkcs7($filePath)
    {
        $res = false;
        if (is_readable($filePath)) {
            preg_match_all('/ByteRange\s*\[(\d+) (\d+) (\d+)/', file_get_contents($filePath), $bytes);
            if ($bytes[2][0] ?? $bytes[3][0] ?? false) {
                $start = $bytes[2][0];
                $end = $bytes[3][0];
                $stream = fopen($filePath, 'rb');
                $res = hex2bin(stream_get_contents($stream, $end - $start - 2, $start + 1));
                fclose($stream);
            }
        } else {
            throw new \Exception("Couldn't open file {$filePath}.");
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
}
