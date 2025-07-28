using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VCBACQHUB_Sample_JWE_JWS.Jwt
{
    public class JweObject
    {
        public string alg { get; set; }
        public string kid { get; set; }
        public string typ { get; set; }
        public string enc { get; set; }
        public string publicKey { get; set; }
        public string privateKey { get; set; }
    }
}
