using Newtonsoft.Json;
using System;
using VCBACQHUB_Sample_JWE_JWS.Utils;

namespace VCBACQHUB_Sample_JWE_JWS.Jwt
{
    public class JwtServices
    {
        private static readonly log4net.ILog Logger =
            log4net.LogManager.GetLogger(typeof(JwtServices));
        public JweObject _jweObjectAlipay2Vcb { get; }
        public JwsObject _jwsObjectAlipay2Vcb { get; }
        public JweObject _jweObjectVcb2Alipay { get; }
        public JwsObject _jwsObjectVcb2Alipay { get; }
        public JwtServices(JweObject jweObjectAlipay2Vcb, JwsObject jwsObjectAlipay2Vcb, JweObject jweObjectVcb2Alipay, JwsObject jwsObjectVcb2Alipay)
        {
            Logger.Info($"JwtServices Initializing...");
            _jweObjectAlipay2Vcb = jweObjectAlipay2Vcb;
            _jwsObjectAlipay2Vcb = jwsObjectAlipay2Vcb;
            _jweObjectVcb2Alipay = jweObjectVcb2Alipay;
            _jwsObjectVcb2Alipay = jwsObjectVcb2Alipay;
            Logger.Debug($"JwtServices jweObjectAlipay2Vcb {JsonConvert.SerializeObject(jweObjectAlipay2Vcb)}");
            Logger.Debug($"JwtServices jwsObjectAlipay2Vcb {JsonConvert.SerializeObject(jwsObjectAlipay2Vcb)}");
            Logger.Debug($"JwtServices jweObjectVcb2Alipay {JsonConvert.SerializeObject(jweObjectVcb2Alipay)}");
            Logger.Debug($"JwtServices jwsObjectVcb2Alipay {JsonConvert.SerializeObject(jwsObjectVcb2Alipay)}");
        }
        public string ValidateJws(string requestID, string signData)
        {
            Logger.Debug($"[{requestID}] ValidateJws {signData}");
            try
            {
                
                string jwsHeader = string.Empty;
                string jwsContent = string.Empty;
                JwsPayload.ValidateJws(requestID, signData, RsaUtils.GetPublicKey(requestID, _jwsObjectVcb2Alipay.publicKey), out jwsHeader, out jwsContent);

                return jwsContent;

            }
            catch (Exception ex)
            {
                Logger.Warn($"[{requestID}] Exception: {ex.Message}");
                Logger.Error($"[{requestID}] Exception: {JsonConvert.SerializeObject(ex)}");
                return string.Empty;
            }
        }
        public string GenerateJws(string requestID, string dataToSigning)
        {
            try
            {
                Logger.Debug($"[{requestID}] GenerateJws by kid: {_jwsObjectAlipay2Vcb.kid}");
                var jwsHeader = JwsPayload.CreateJwsHeader(_jwsObjectAlipay2Vcb.alg, _jwsObjectAlipay2Vcb.kid, _jwsObjectAlipay2Vcb.typ, _jwsObjectAlipay2Vcb.cty);

                return JwsPayload.GenerateJws(requestID, dataToSigning, jwsHeader, RsaUtils.GetPrivateKey(requestID, _jwsObjectAlipay2Vcb.privateKey));
            }
            catch (Exception ex)
            {
                Logger.Warn($"[{requestID}] Exception: {ex.Message}");
                Logger.Error($"[{requestID}] Exception: {JsonConvert.SerializeObject(ex)}");
                return string.Empty;
            }
        }
        public string DecryptJwe(string requestID, string encryptData)
        {
            Logger.Debug($"[{requestID}] DecryptJwe");
            try
            {
                return JwePayload.DecryptJwe(encryptData, RsaUtils.GetPrivateKey(requestID, _jweObjectVcb2Alipay.privateKey));
            }
            catch (Exception ex)
            {
                Logger.Warn($"[{requestID}] Exception: {ex.Message}");
                Logger.Error($"[{requestID}] Exception: {JsonConvert.SerializeObject(ex)}");
                return string.Empty;
            }
        }
        public string EncryptJwe(string requestID, string data)
        {
            Logger.Debug($"[{requestID}] EncryptJwe: {data}");
            try
            {
                var jweHeader = JwePayload.CreateJweHeader(_jweObjectAlipay2Vcb.alg, _jweObjectAlipay2Vcb.kid, _jweObjectAlipay2Vcb.typ, _jweObjectAlipay2Vcb.enc, GetTimeStamp());

                return JwePayload.EncryptJwe(data, jweHeader, RsaUtils.GetPublicKey(requestID, _jweObjectAlipay2Vcb.publicKey));
            }
            catch (Exception ex)
            {
                Logger.Warn($"[{requestID}] Exception: {ex.Message}");
                Logger.Error($"[{requestID}] Exception: {JsonConvert.SerializeObject(ex)}");
                return string.Empty;
            }
        }
        private static string GetTimeStamp()
        {
            long timeStamp = ((long)DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalMilliseconds) / 1000;

            return timeStamp.ToString();
        }
    }
}
