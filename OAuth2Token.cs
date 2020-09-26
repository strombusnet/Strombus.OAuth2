using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Strombus.OAuth2
{
    public class OAuth2Token
    {
        public string Id { set; get; }
        public DateTimeOffset? ExpiresAt { set; get; }

        public OAuth2Token()
        {
        }
    }
}
