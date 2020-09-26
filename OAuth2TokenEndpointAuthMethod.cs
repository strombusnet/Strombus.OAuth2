using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Strombus.OAuth2
{
    public enum OAuth2TokenEndpointAuthMethod
    {
        None,              // public client (no client secret; does not use token endpoint)
        ClientSecretBasic, // default (use bearer token in Authorization header)
        ClientSecretPost,  // use bearer token in HTTP POST parameter
    }

    public partial class OAuth2Convert
    {
        private const string TOKEN_ENDPOINT_AUTH_METHOD_NONE = "none";
        private const string TOKEN_ENDPOINT_AUTH_METHOD_CLIENT_SECRET_BASIC = "client_secret_basic";
        private const string TOKEN_ENDPOINT_AUTH_METHOD_CLIENT_SECRET_POST = "client_secret_post";

        public static string ConvertTokenEndpointAuthMethodToString(OAuth2TokenEndpointAuthMethod value)
        {
            switch (value)
            {
                case OAuth2TokenEndpointAuthMethod.None:
                    return TOKEN_ENDPOINT_AUTH_METHOD_NONE;
                case OAuth2TokenEndpointAuthMethod.ClientSecretBasic:
                    return TOKEN_ENDPOINT_AUTH_METHOD_CLIENT_SECRET_BASIC;
                case OAuth2TokenEndpointAuthMethod.ClientSecretPost:
                    return TOKEN_ENDPOINT_AUTH_METHOD_CLIENT_SECRET_POST;
                default:
                    return null;
            }
        }

        public static OAuth2TokenEndpointAuthMethod? ConvertStringToTokenEndpointAuthMethod(string value)
        {
            switch (value)
            {
                case TOKEN_ENDPOINT_AUTH_METHOD_NONE:
                    return OAuth2TokenEndpointAuthMethod.None;
                case TOKEN_ENDPOINT_AUTH_METHOD_CLIENT_SECRET_BASIC:
                    return OAuth2TokenEndpointAuthMethod.ClientSecretBasic;
                case TOKEN_ENDPOINT_AUTH_METHOD_CLIENT_SECRET_POST:
                    return OAuth2TokenEndpointAuthMethod.ClientSecretPost;
                default:
                    return null;
            }
        }

    }
}
