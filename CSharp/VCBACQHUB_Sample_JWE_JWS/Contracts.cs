using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace VCBACQHUB_Sample_JWE_JWS
{
    public class VCB_JWT
    {
        public string access_token { get; set; }
        public string token_type { get; set; }
        public int expires_in { get; set; }

        [JsonProperty(".issued")]
        public DateTime issued { get; set; }

        [JsonProperty(".expires")]
        public DateTime expires { get; set; }
    }

    public class MessageHeader
    {
        public string id { get; set; }
        public string recipient { get; set; }
        public string sender { get; set; }
        public DateTime ts { get; set; }
        public string exchangeId { get; set; }
    }

    public class InquiryEncryptedExchangeRateParameter
    {
        public MessageHeader header { get; set; }
        public string encryptedPayload { get; set; }
    }

    public class InquiryEncryptedExchangeRateResponseContent
    {
        public MessageHeader header { get; set; }
        public string encryptedPayload { get; set; }
    }

    public class InquiryExchangeRateParameter
    {
        public MessageHeader header { get; set; }
        public InquiryExchangeRateRequestPayload payload { get; set; }
    }

    public class InquiryExchangeRateRequestPayload
    {
        public string mid { get; set; }
        public string tid { get; set; }
        public string partnerCode { get; set; }
        public string fxRateType { get; set; }
        public string currencyCode { get; set; }
        public string exchangeCurrencyCode { get; set; }
        public string referenceId { get; set; }
    }
}
