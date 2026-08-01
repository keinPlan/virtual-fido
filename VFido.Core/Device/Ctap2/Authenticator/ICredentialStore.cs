using System.Collections.Generic;

namespace VFido.Core.Device.Ctap2.Authenticator
{
    internal interface ICredentialStore
    {
        void Save(StoredCredential credential);
        StoredCredential? Find(byte[] credentialId);
        IReadOnlyList<StoredCredential> FindByRp(string rpId);
    }
}
