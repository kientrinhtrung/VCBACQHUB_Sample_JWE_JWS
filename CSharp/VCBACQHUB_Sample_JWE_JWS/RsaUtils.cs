using Chilkat;
using System;

namespace VCBACQHUB_Sample_JWE_JWS.Utils
{
    public class RsaUtils
    {
        private static readonly log4net.ILog Logger =
            log4net.LogManager.GetLogger(typeof(RsaUtils));
        // ----------------------------------
        // Reaing the public key
        public static PublicKey GetPublicKey(string requestID, string filePath)
        {
            //Logger.Debug($"[{requestID}] GetPublicKey file: {filePath}");
            Cert cert = new Cert();

            bool success = cert.LoadFromFile(filePath);
            if (success != true)
            {
                Logger.Error($"[{requestID}] Load failed");
                return null;
            }

            PublicKey rsaPubKey = cert.ExportPublicKey();
            if (cert.LastMethodSuccess != true)
            {
                Logger.Error($"[{requestID}] LastMethodSuccess failed");
                return null;
            }
            //Logger.Debug($"[{requestID}] done");
            return rsaPubKey;
        }
        public static PrivateKey GetPrivateKey(string requestID, string filePath)
        {
            //Logger.Debug($"[{requestID}] GetPrivateKey file: {filePath}");
            PrivateKey rsaPrivateKey = new PrivateKey();

            bool success = rsaPrivateKey.LoadPemFile(filePath);
            if (success != true)
            {
                Logger.Error($"[{requestID}] Load failed");
                return null;
            }
            //Logger.Debug($"[{requestID}] Done");
            return rsaPrivateKey;
        }
    }
}
