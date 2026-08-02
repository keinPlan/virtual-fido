using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace VFido.SecretManager.Crypto
{
    /// <summary>
    /// Builds the self-signed attestation chain a virtual stick presents in a "packed" attestation
    /// statement's x5c: a root CA, an intermediate CA it issues, and a leaf attestation certificate
    /// the intermediate issues in turn. There's no real FIDO Alliance-issued batch certificate
    /// behind this - it's a locally generated substitute so relying parties that expect x5c to be
    /// present still get a coherent, verifiable chain. The root is kept out of x5c (it's the trust
    /// anchor a relying party would need out-of-band anyway); only the intermediate and leaf are sent.
    /// </summary>
    public static class AttestationCertificateFactory
    {
        public const string RootSubjectName = "CN=VirtualSecurity Root CA";
        public const string IntermediateSubjectName = "CN=VirtualSecurity Attestation CA, O=VirtualFido";

        // CTAP2 attestation certificate requirements (§5.1): Subject-C/O/OU/CN are all mandated on
        // the batch (leaf) attestation certificate specifically - root/intermediate CAs aren't held
        // to this shape.
        public const string LeafSubjectName = "CN=VirtualFido Virtual Authenticator, OU=Authenticator Attestation, O=VirtualFido, C=AT";

        private static readonly TimeSpan Validity = TimeSpan.FromDays(20 * 365);

        /// <summary>Self-signs <paramref name="rootKey"/> into a DER-encoded root CA certificate.</summary>
        public static byte[] CreateSelfSignedRoot(ECDsa rootKey)
        {
            var request = new CertificateRequest(RootSubjectName, rootKey, HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: true, hasPathLengthConstraint: true, pathLengthConstraint: 1, critical: true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, critical: true));
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

            var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
            using var root = request.CreateSelfSigned(notBefore, notBefore + Validity);
            return root.Export(X509ContentType.Cert);
        }

        /// <summary>Issues a DER-encoded intermediate CA certificate for <paramref name="intermediateKey"/>, signed by the root behind <paramref name="rootKey"/>/<paramref name="rootCertificateDer"/>.</summary>
        public static byte[] CreateIntermediate(ECDsa intermediateKey, ECDsa rootKey, byte[] rootCertificateDer)
        {
            var request = new CertificateRequest(IntermediateSubjectName, intermediateKey, HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: true, hasPathLengthConstraint: true, pathLengthConstraint: 0, critical: true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, critical: true));
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

            return Issue(request, rootKey, rootCertificateDer);
        }

        /// <summary>Issues a DER-encoded leaf attestation certificate for <paramref name="leafKey"/>, signed by the intermediate behind <paramref name="intermediateKey"/>/<paramref name="intermediateCertificateDer"/>.</summary>
        public static byte[] CreateAttestationLeaf(ECDsa leafKey, ECDsa intermediateKey, byte[] intermediateCertificateDer)
        {
            var request = new CertificateRequest(LeafSubjectName, leafKey, HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: false, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

            return Issue(request, intermediateKey, intermediateCertificateDer);
        }

        private static byte[] Issue(CertificateRequest request, ECDsa issuerKey, byte[] issuerCertificateDer)
        {
            using var issuer = new X509Certificate2(issuerCertificateDer);
            using var issuerWithPrivateKey = issuer.CopyWithPrivateKey(issuerKey);

            var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
            var serialNumber = RandomNumberGenerator.GetBytes(16);
            using var issued = request.Create(issuerWithPrivateKey, notBefore, notBefore + Validity, serialNumber);
            return issued.Export(X509ContentType.Cert);
        }
    }
}
