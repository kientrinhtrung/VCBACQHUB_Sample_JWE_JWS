using Chilkat;
using System;
using System.Collections.Generic;
using System.Text;

namespace VCBACQHUB_Sample_JWE_JWS.Jwt
{
    public class JwsPayload
    {
        private static readonly log4net.ILog Logger =
        log4net.LogManager.GetLogger(typeof(JwsPayload));
        public static JsonObject CreateJwsHeader(string alg, string kid, string typ, string cty)
        {
            JsonObject jwsProtHdr = new JsonObject();
            jwsProtHdr.AppendString("alg", alg);
            jwsProtHdr.AppendString("kid", kid);
            jwsProtHdr.AppendString("typ", typ);
            jwsProtHdr.AppendString("cty", cty);
            return jwsProtHdr;
        }
        public static string GenerateJws(string requestID, string payload, JsonObject jwsProtHdr, PrivateKey rsaPrivateKey)
        {
            Jws jws = new Jws();
            jws.SetProtectedHeader(0, jwsProtHdr);
            jws.SetPrivateKey(0, rsaPrivateKey);
            jws.SetPayload(payload, "utf-8", false);

            string jwsCompact = jws.CreateJws();
            if (jws.LastMethodSuccess != true)
            {
                Logger.Warn($"[{requestID}] GenerateJws false {payload}");
                return string.Empty;
            }

            return jwsCompact;
        }
        public static void ValidateJws(string requestID, string strJws, PublicKey rsaPublicKey, out string jwsHeader, out string jwsContent)
        {
            Jws jws = new Jws();
            jwsHeader = string.Empty;
            jwsContent = string.Empty;

            // Set the RSA Public Key
            jws.SetPublicKey(0, rsaPublicKey);

            // Load the JWS
            bool success = jws.LoadJws(strJws);
            if (success != true)
            {
                Logger.Warn($"[{requestID}] LoadJws false");
                return;
            }

            //  Validate the 1st (and only) signature at index 0..
            int v = jws.Validate(0);

            //  Perhaps Chilkat was not unlocked or the trial expired..
            if (v < 0)
            {
                Logger.Warn($"[{requestID}] Validate false {v}");
                return;
            }
            // Invalid signature.  The RSA key was incorrect, the JWS was invalid, or both.
            if (v == 0)
            {
                Logger.Warn($"[{requestID}] Validate false {v}");
                return;
            }

            //  If we get here, the signature was validated..
            //  Recover the original content:
            jwsContent = jws.GetPayload("utf-8");

            //  Examine the protected header:
            JsonObject joseHeader = jws.GetProtectedHeader(0);
            // No protected header found at the given index.
            if (jws.LastMethodSuccess != true)
            {
                Logger.Warn($"[{requestID}] GetProtectedHeader false");
                return;
            }

            joseHeader.EmitCompact = false;
            jwsHeader = joseHeader.Emit();
        }
    }
}
