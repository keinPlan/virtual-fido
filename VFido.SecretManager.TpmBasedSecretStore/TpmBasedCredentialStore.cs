using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Tpm2Lib;
using VFido.Core.Protocol.Helper;

namespace VFido.SecretManager.TpmBasedSecretStore
{
 
    public class TpmBasedCredentialStore : ICredentialStore
    {
        public void Delete(byte[] credentialId)
        {
            throw new NotImplementedException();
        }

        public StoredCredential? Find(byte[] credentialId)
        {
            throw new NotImplementedException();
        }

        public IReadOnlyList<StoredCredential> FindAll()
        {
            throw new NotImplementedException();
        }

        public IReadOnlyList<StoredCredential> FindByRp(string rpId)
        {
            throw new NotImplementedException();
        }

        public void Save(StoredCredential credential)
        {
            throw new NotImplementedException();
        }
    }

    public class TpmBasedSecretStore : IKeyStore
    {
        public byte[] Aaguid => throw new NotImplementedException();

        public ISigningKey CreateEs256Key()
        {
            throw new NotImplementedException();
        }

        public void DeleteKey(byte[] handle)
        {
            throw new NotImplementedException();
        }

        public AttestationCertificate GetOrCreateAttestationCertificate()
        {
            throw new NotImplementedException();
        }

        public ISigningKey LoadKey(byte[] handle)
        {
            throw new NotImplementedException();
        }
    }

    public class TpmBasedSigningKey : ISigningKey
    {
        private const int AlgEs256 = -7;
         public int CoseAlgorithm => AlgEs256;

        public TpmBasedSigningKey(uint keyhandle ,string keyPassword, object keyblob)
        {
            Tpm2Device device = new TbsDevice();   // or LinuxTpmDevice / TcpTpmDevice
            device.Connect();
            using var tpm = new Tpm2(device);

            var aes = new TpmHandle(keyhandle) { Auth = Encoding.UTF8.GetBytes("keyPassword") };

        }

        public byte[] ExportCosePublicKey()
        {
            throw new NotImplementedException();
        }

        public byte[] ExportHandle()
        {
            throw new NotImplementedException();
        }

        public byte[] Sign(byte[] data)
        {
            throw new NotImplementedException();
        }
    }
}
