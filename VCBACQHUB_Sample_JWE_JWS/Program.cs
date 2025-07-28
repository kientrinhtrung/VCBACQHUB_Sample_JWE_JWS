using System;
using System.Collections;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics.Contracts;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using log4net;
using log4net.Repository.Hierarchy;
using Newtonsoft.Json;
using RestSharp;
using VCBACQHUB_Sample_JWE_JWS.Jwt;

namespace VCBACQHUB_Sample_JWE_JWS
{
    internal class Program
    {
        public static JwtServices JWEJWS;
        private static readonly ILog Logger = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
        public static VCB_JWT JWT = null;
        public static string PARTNER_CODE = ConfigurationManager.AppSettings["PARTNER_CODE"];
        public static string VERSION_CODE = ConfigurationManager.AppSettings["VERSION_CODE"];
        public static string CLIENT_ID = ConfigurationManager.AppSettings["CLIENT_ID"];
        public static string CLIENT_SECRET = ConfigurationManager.AppSettings["CLIENT_SECRET"];
        public static string GRANT_TYPE = ConfigurationManager.AppSettings["GRANT_TYPE"];
        public static string MID = ConfigurationManager.AppSettings["MID"];
        public static string TID = ConfigurationManager.AppSettings["TID"];
        public static string URL_OAUTH_TOKEN = ConfigurationManager.AppSettings["URL_OAUTH_TOKEN"];
        public static string URL_INQUIRY_EXCHANGE_RATE = ConfigurationManager.AppSettings["URL_INQUIRY_EXCHANGE_RATE"];
        public static void Main(string[] args)
        {
            log4net.Config.XmlConfigurator.Configure();
            var RequestID = Guid.NewGuid().ToString();
            if (JWEJWS == null)
            {
                JweObject jweAlipay2Vcb = new JweObject();
                jweAlipay2Vcb.alg = ConfigurationManager.AppSettings["ALIPAY2VCB_JWE_ALG"];
                jweAlipay2Vcb.kid = ConfigurationManager.AppSettings["ALIPAY2VCB_JWE_KID"];
                jweAlipay2Vcb.typ = ConfigurationManager.AppSettings["ALIPAY2VCB_JWE_TYP"];
                jweAlipay2Vcb.enc = ConfigurationManager.AppSettings["ALIPAY2VCB_JWE_ENC"];
                jweAlipay2Vcb.publicKey = ConfigurationManager.AppSettings["ALIPAY2VCB_JWE_PUBLICKEY"];
                jweAlipay2Vcb.privateKey = ConfigurationManager.AppSettings["ALIPAY2VCB_JWE_PRIVATEKEY"];
                
                JwsObject jwsAlipay2Vcb = new JwsObject();
                jwsAlipay2Vcb.alg = ConfigurationManager.AppSettings["ALIPAY2VCB_JWS_ALG"];
                jwsAlipay2Vcb.kid = ConfigurationManager.AppSettings["ALIPAY2VCB_JWS_KID"];
                jwsAlipay2Vcb.typ = ConfigurationManager.AppSettings["ALIPAY2VCB_JWS_TYP"];
                jwsAlipay2Vcb.cty = ConfigurationManager.AppSettings["ALIPAY2VCB_JWS_CTY"];
                jwsAlipay2Vcb.publicKey = ConfigurationManager.AppSettings["ALIPAY2VCB_JWS_PUBLICKEY"];
                jwsAlipay2Vcb.privateKey = ConfigurationManager.AppSettings["ALIPAY2VCB_JWS_PRIVATEKEY"];

                JweObject jweVcb2Alipay = new JweObject();
                jweVcb2Alipay.alg = ConfigurationManager.AppSettings["VCB2ALIPAY_JWE_ALG"];
                jweVcb2Alipay.kid = ConfigurationManager.AppSettings["VCB2ALIPAY_JWE_KID"];
                jweVcb2Alipay.typ = ConfigurationManager.AppSettings["VCB2ALIPAY_JWE_TYP"];
                jweVcb2Alipay.enc = ConfigurationManager.AppSettings["VCB2ALIPAY_JWE_ENC"];
                jweVcb2Alipay.publicKey = ConfigurationManager.AppSettings["VCB2ALIPAY_JWE_PUBLICKEY"];
                jweVcb2Alipay.privateKey = ConfigurationManager.AppSettings["VCB2ALIPAY_JWE_PRIVATEKEY"];
                
                JwsObject jwsVcb2Alipay = new JwsObject();
                jwsVcb2Alipay.alg = ConfigurationManager.AppSettings["VCB2ALIPAY_JWS_ALG"];
                jwsVcb2Alipay.kid = ConfigurationManager.AppSettings["VCB2ALIPAY_JWS_KID"];
                jwsVcb2Alipay.typ = ConfigurationManager.AppSettings["VCB2ALIPAY_JWS_TYP"];
                jwsVcb2Alipay.cty = ConfigurationManager.AppSettings["VCB2ALIPAY_JWS_CTY"];
                jwsVcb2Alipay.publicKey = ConfigurationManager.AppSettings["VCB2ALIPAY_JWS_PUBLICKEY"];
                jwsVcb2Alipay.privateKey = ConfigurationManager.AppSettings["VCB2ALIPAY_JWS_PRIVATEKEY"];

                JWEJWS = new JwtServices(jweAlipay2Vcb, jwsAlipay2Vcb, jweVcb2Alipay, jwsVcb2Alipay);
            }

            var header = new MessageHeader
            {
                id = RequestID,
                sender = "ALIPAY",
                recipient = "VIETCOMBANK",
                exchangeId = Guid.NewGuid().ToString(),
                ts = DateTime.Now
            };
            var req = new InquiryEncryptedExchangeRateParameter
            {
                header = header
            };

            var payload = new InquiryExchangeRateRequestPayload
            { 
                mid = MID, 
                tid = TID, 
                partnerCode = PARTNER_CODE, 
                referenceId = Guid.NewGuid().ToString(),
                currencyCode = "USD", 
                exchangeCurrencyCode = "VND",
                fxRateType = "SELL"
            };

            var jwe = JWEJWS.EncryptJwe(RequestID, JsonConvert.SerializeObject(payload, Formatting.None, new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore }));
            Logger.Debug($"[{RequestID}] jwe: {jwe}");

            var jws = JWEJWS.GenerateJws(RequestID, jwe);
            Logger.Debug($"[{RequestID}] jws: {jws}");

            req.encryptedPayload = jws;

            var rsp = SendInquiryExchangeRateToVCB(req);
            if (rsp != null)
            {
                Logger.Debug($"Done");
                var jwsContent = JWEJWS.ValidateJws(RequestID, rsp.encryptedPayload);
                if (!string.Empty.Equals(jwsContent))
                {
                    var encryptedPayload = JWEJWS.DecryptJwe(RequestID, jwsContent);
                    var encryptedData = JsonConvert.DeserializeObject<InquiryExchangeRateRequestPayload>(encryptedPayload);
                    if (encryptedData == null)
                    {
                        Logger.Info($"[{RequestID}] DecryptJwe Failed");
                    }
                    Logger.Info($"[{RequestID}] payload {encryptedPayload}");
                }
                else
                {
                    Logger.Info($"[{RequestID}] ValidateJws Failed");
                }
            }
            else
            {
                Logger.Warn("Failed");
            }

            Console.ReadKey();
        }

        public static void LoginJWT()
        {
            Logger.Debug("LoginJWT");
            var client = new RestClient();
            var request = new RestRequest(URL_OAUTH_TOKEN, Method.Post);
            request.AddHeader("Content-Type", "application/x-www-form-urlencoded");
            request.AddParameter("client_id", CLIENT_ID);
            request.AddParameter("client_secret", CLIENT_SECRET);
            request.AddParameter("grant_type", GRANT_TYPE);
            Logger.Debug($"URL_OAUTH_TOKEN: {URL_OAUTH_TOKEN}");
            Logger.Debug($"CLIENT:  {CLIENT_ID}/{CLIENT_SECRET}");
            RestResponse response = client.Execute(request);
            Logger.Debug($"StatusCode: {JsonConvert.SerializeObject(response.StatusCode)}");
            Logger.Debug($"Content: {JsonConvert.SerializeObject(response.Content)}");
            if (response != null && response.StatusCode == HttpStatusCode.OK && !String.IsNullOrEmpty(response.Content))
            {
                JWT = JsonConvert.DeserializeObject<VCB_JWT>(response.Content);
            }
        }

        public static InquiryEncryptedExchangeRateResponseContent SendInquiryExchangeRateToVCB(InquiryEncryptedExchangeRateParameter parameter)
        {
            Logger.Debug("SendInquiryExchangeRateToVCB");
            var client = new RestClient();
            var url = String.Format(URL_INQUIRY_EXCHANGE_RATE, VERSION_CODE, PARTNER_CODE);
            Logger.Debug($"URL_INQUIRY_EXCHANGE_RATE: {url}");
            var request = new RestRequest(url, Method.Post);
            request.AddHeader("Content-Type", "application/json");
            if (JWT == null || String.IsNullOrEmpty(JWT.access_token) || JWT.expires >= DateTime.Now.AddMinutes(-1))
                LoginJWT();
            request.AddHeader("Authorization", $"{JWT.token_type} {JWT.access_token}");
            var body = JsonConvert.SerializeObject(parameter);
            request.AddStringBody(body, DataFormat.Json);
            RestResponse response = client.Execute(request);
            Logger.Debug($"StatusCode: {JsonConvert.SerializeObject(response.StatusCode)}");
            Logger.Debug($"Content: {JsonConvert.SerializeObject(response.Content)}");
            if (response != null && response.StatusCode == HttpStatusCode.OK && !String.IsNullOrEmpty(response.Content))
            {
                return JsonConvert.DeserializeObject<InquiryEncryptedExchangeRateResponseContent>(response.Content);
            }
            else
                return null;
        }
    }
}
