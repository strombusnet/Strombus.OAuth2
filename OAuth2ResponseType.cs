using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Strombus.OAuth2
{
    internal enum OAuth2ResponseType
    {
        Code,
        Token
    }

    public partial class OAuth2Convert
    {
        private const string RESPONSE_TYPE_CODE = "code";
        private const string RESPONSE_TYPE_TOKEN = "token";

        internal static string ConvertResponseTypeToString(OAuth2ResponseType value)
        {
            switch (value)
            {
                case OAuth2ResponseType.Code:
                    return RESPONSE_TYPE_CODE;
                case OAuth2ResponseType.Token:
                    return RESPONSE_TYPE_TOKEN;
                default:
                    return null;
            }
        }

        internal static OAuth2ResponseType? ConvertStringToResponseType(string value)
        {
            switch (value)
            {
                case RESPONSE_TYPE_CODE:
                    return OAuth2ResponseType.Code;
                case RESPONSE_TYPE_TOKEN:
                    return OAuth2ResponseType.Token;
                default:
                    return null;
            }
        }
    }
}
