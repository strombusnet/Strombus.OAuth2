using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Strombus.OAuth2
{
    public enum OAuth2GrantType
    {
        AuthorizationCode, // default (use authorization code flow)
        Implicit,          // implicit flow (for web browsers, etc.)
        Password,          // username/password login (we only allow this for trusted first-party clients)
        ClientCredentials, // server to server flow, using manually-entered OAuth2 credentials
        RefreshToken       // refresh grant
    }

    public partial class OAuth2Convert
    {
        private const string GRANT_TYPE_STRING_AUTHORIZATION_CODE = "authorization_code";
        private const string GRANT_TYPE_STRING_IMPLICIT = "implicit";
        private const string GRANT_TYPE_STRING_RESOURCE_OWNER_PASSWORD_CREDENTIALS = "password";
        private const string GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials";
        private const string GRANT_TYPE_REFRESH_TOKEN = "refresh_token";

        public static string ConvertGrantTypeToString(OAuth2GrantType value)
        {
            switch (value)
            {
                case OAuth2GrantType.AuthorizationCode:
                    return GRANT_TYPE_STRING_AUTHORIZATION_CODE;
                case OAuth2GrantType.ClientCredentials:
                    return GRANT_TYPE_CLIENT_CREDENTIALS;
                case OAuth2GrantType.Implicit:
                    return GRANT_TYPE_STRING_IMPLICIT;
                case OAuth2GrantType.Password:
                    return GRANT_TYPE_STRING_RESOURCE_OWNER_PASSWORD_CREDENTIALS;
                case OAuth2GrantType.RefreshToken:
                    return GRANT_TYPE_REFRESH_TOKEN;
                default:
                    return null;
            }
        }

        public static OAuth2GrantType? ConvertStringToGrantType(string value)
        {
            switch (value)
            {
                case GRANT_TYPE_STRING_AUTHORIZATION_CODE:
                    return OAuth2GrantType.AuthorizationCode;
                case GRANT_TYPE_CLIENT_CREDENTIALS:
                    return OAuth2GrantType.ClientCredentials;
                case GRANT_TYPE_STRING_IMPLICIT:
                    return OAuth2GrantType.Implicit;
                case GRANT_TYPE_STRING_RESOURCE_OWNER_PASSWORD_CREDENTIALS:
                    return OAuth2GrantType.Password;
                case GRANT_TYPE_REFRESH_TOKEN:
                    return OAuth2GrantType.RefreshToken;
                default:
                    return null;
            }
        }
    }
}
