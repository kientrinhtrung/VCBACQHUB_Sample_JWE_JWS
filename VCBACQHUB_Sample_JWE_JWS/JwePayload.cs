using Chilkat;
using System;

namespace VCBACQHUB_Sample_JWE_JWS.Jwt
{
    public class JwePayload
    {
        //  ---------------------------------
        //  A.1.1 JOSE Header
        //  First build the JWE Protected Header.
        public static JsonObject CreateJweHeader(string alg, string kid, string typ, string enc, string iat)
        {
            JsonObject jweProtHdr = new JsonObject();
            jweProtHdr.AppendString("alg", alg);
            jweProtHdr.AppendString("kid", kid);
            jweProtHdr.AppendString("typ", typ);
            jweProtHdr.AppendString("enc", enc);
            jweProtHdr.AppendString("iat", iat);
            return jweProtHdr;
        }
        //  ---------------------------------
        //  A.1.2 Content Encryption Key
        //  Note: Chilkat automatically generates the random CEK internally.
        //  The application does not need to explicitly take this step.

        //  ---------------------------------
        //  A.1.3.  Key Encryption
        //  The application should load an RSA private key from any format.
        //  However, the application does not need to explicitly construct the JWE Encrypted Key.
        //  Chilkat automatically does it internally.
        //  The design of the Chilkat JWE API is to allow the application to create the JWE
        //  after specifying the inputs.  (This is in contrast to forcing the application developer
        //  to painstakingly go through each step of the JWE construction process.)

        //  ---------------------------------
        //  A.1.4.  Initialization Vector
        //  Chilkat automatically generates the necessary random IV internally.
        //  The application does not need to do this explicitly.

        //  ---------------------------------
        //  A.1.5.  Additional Authenticated Data
        //  The Additional Authenticated Data encryption parameter is
        //  ASCII(BASE64URL(UTF8(JWE Protected Header))).
        //  Again, Chilkat automatically takes care of this internally.
        //  The application does not need to explicitly take this step.

        //  ---------------------------------
        //  A.1.6.  Content Encryption
        //  Again... this step is handled by Chilkat internally.

        //  ---------------------------------
        //  A.1.7.  Complete Representation
        //  The application need only call the Encrypt, EncryptSb, or EncryptBd method
        //  return the fully assembled JWE.
        //  The final representation in the Compact Serialization
        //  is the string BASE64URL(UTF8(JWE Protected Header)) || '.' ||
        //  BASE64URL(JWE Encrypted Key) || '.' || BASE64URL(JWE Initialization
        //  Vector) || '.' || BASE64URL(JWE Ciphertext) || '.' || BASE64URL(JWE
        //  Authentication Tag).
        public static string EncryptJwe(string payload, JsonObject jweProtHdr, PublicKey rsaPubKey)
        {
            Jwe jwe = new Jwe();
            // Set Proceted Header
            jwe.SetProtectedHeader(jweProtHdr);
            // Set Public Key used for encrypt
            jwe.SetPublicKey(0, rsaPubKey);
            // Encrypt payload using JWE
            string strJwe = jwe.Encrypt(payload, "utf-8");
            if (jwe.LastMethodSuccess != true)
            {
                return string.Empty;
            }

            return strJwe;
        }
        //  Let's decrypt the JWE that was just produced.
        //  Do the following to decrypt a JWE:
        //  1) Load the JWE.
        //  2) Set the private key for decryption.
        //  3) Decrypt.
        public static string DecryptJwe(string strJwe, PrivateKey rsaPrivKey)
        {
            //  1) Load the JWE.
            Jwe jwe = new Jwe();
            bool success = jwe.LoadJwe(strJwe);
            if (success != true)
            {
                return string.Empty;
            }

            //  Provide the RSA private key for decryption.
            //  (The JWE was encrypted for a single recipient at index 0.)
            //  2) Set the private key for decryption.
            jwe.SetPrivateKey(0, rsaPrivKey);

            //  Decrypt.
            string originalPlaintext = jwe.Decrypt(0, "utf-8");
            if (jwe.LastMethodSuccess != true)
            {
                return string.Empty;
            }

            return originalPlaintext;
        }
    }
}
