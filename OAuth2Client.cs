using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.Web.Http;

namespace Strombus.OAuth2
{
    public class OAuth2Client
    {
        //const int HTTP_STATUS_CODE_200_OK = 200;
        //const int HTTP_STATUS_CODE_201_CREATED = 201;
        //const int HTTP_STATUS_CODE_400_BAD_REQUEST = 400;
        //const int HTTP_STATUS_CODE_402_PAYMENT_REQUIRED = 402;
        //const int HTTP_STATUS_CODE_403_FORBIDDEN = 403;
        //const int HTTP_STATUS_CODE_429_TOO_MANY_REQUESTS = 429;
        //const int HTTP_STATUS_CODE_500_INTERNAL_SERVER_ERROR = 500;
        //const int HTTP_STATUS_CODE_503_SERVICE_UNAVAILABLE = 503;

        private struct OAuth2ErrorResponse
        {
            public string error;
            public string error_description;
        }

        public string Id { set; get; }
        public string Secret { set; get; }
        public DateTimeOffset? IssuedAt { set; get; }
        public DateTimeOffset? SecretExpiresAt { set; get; }
        public string SoftwareId { set; get; }
        public string SoftwareVersion { set; get; }
        public List<string> RedirectUris { set; get; }
        public OAuth2TokenEndpointAuthMethod TokenEndpointAuthMethod { set; get; }
        public List<OAuth2GrantType> GrantTypes { set; get; }
        public string Scope { set; get; }
        public string RegistrationUri { set; get; }
        public string RegistrationToken { set; get; }

        public OAuth2Client()
        {
        }

        #region "Client Registration Endpoint"

        private struct RegisterClientRequest
        {
            public string software_id;
            public string software_version;
            public string[] redirect_uris;
            public string token_endpoint_auth_method;
            public string[] grant_types;
            public string[] response_types;
            public string scope;
        }
        private struct RegisterClientResponse
        {
            public string client_id;
            public string client_secret;
            public long? client_id_issued_at;
            public long? client_secret_expires_at;
            public string software_id;
            public string software_version;
            public string[] redirect_uris;
            public string token_endpoint_auth_method;
            public string[] grant_types;
            public string[] response_types;
            public string scope;
            public string registration_client_uri;
            public string registration_access_token;
        }
        public static async Task<OAuth2Client> RegisterClientAsync(Uri clientRegistrationEndpoint, string initialAccessToken, string softwareId, string softwareVersion, OAuth2TokenEndpointAuthMethod tokenEndpointAuthMethod, List<OAuth2GrantType> grantTypes, List<string> redirectUris, List<string> scopes)
        {
            /* STEP 1: validate all arguments */

            // validate our clientRegistrationEndpoint uri
            if (clientRegistrationEndpoint == null)
            {
                throw new ArgumentNullException(nameof(clientRegistrationEndpoint));
            }
            else if (clientRegistrationEndpoint.Scheme.ToLowerInvariant() != "https")
            {
                throw new ArgumentException("clientRegistrationEndpoint must be secured with the https protocol.", nameof(clientRegistrationEndpoint));
            }

            /* validate redirectUris: make sure that the redirectUris use HTTPS or a non-HTTP protocol (e.g. an app-specific protocol on a mobile 
             * device).  HTTP is also valid with redirectUris--but only for the localhost. */
            if (redirectUris != null)
            {
                for (int iRedirectUri = 0; iRedirectUri < redirectUris.Count; iRedirectUri++)
                {
                    // break the redirectUri down into its components (scheme, host, etc.)
                    Uri uri;
                    try
                    {
                        uri = new Uri(redirectUris[iRedirectUri]);
                    }
                    catch
                    {
                        throw new ArgumentException("redirectUris[" + iRedirectUri + "] is a malformed redirect uri.", nameof(redirectUris));
                    }
                    //
                    if (uri.Host == null)
                    {
                        throw new ArgumentException("redirectUris[" + iRedirectUri + "] is a malformed redirect uri.", nameof(redirectUris));
                    }
                    //
                    switch (uri.Scheme.ToLowerInvariant())
                    {
                        case "http":
                            // HTTP scheme is okay as long as the server is localhost (i.e. communication is on the loopback interface).
                            if (uri.Host != "127.0.0.1" && uri.Host != "::1" && uri.Host.ToLowerInvariant() != "localhost")
                                throw new ArgumentException("redirectUris[" + iRedirectUri + "] must be secured with the https protocol.", nameof(redirectUris));
                            break;
                        case "https":
                            // HTTPS scheme is okay
                            break;
                        default:
                            // custom app-specific schemes are okay
                            break;
                    }
                }
            }

            // validate our scopes: they cannot contain any spaces and they must conform to our "allowable characters" rules.
            if (scopes != null)
            {
                for (int iScope = 0; iScope < scopes.Count; iScope++)
                {
                    if (ContainsOnlyAllowedScopeCharacters(scopes[iScope]) == false)
                    {
                        throw new ArgumentException("scopes[" + iScope + "] may only contain letters, numbers and the following characters: '" + string.Join("', '", _allowedScopeSpecialCharactersAsString.ToArray()) + "'", nameof(scopes));
                    }
                }
            }

            // validate the grantTypes
            /* Supported grantType options (including combinations) are:
             * .AuthorizationCode
             * .AuthorizationCode, .RefreshToken
             * .Implicit
             * .Password
             * .Password, .RefreshToken
             * .ClientCredentials */
            OAuth2GrantType grantType;
            bool requestRefreshTokenGrantType = false;
            if (grantTypes == null || grantTypes.Count == 0)
            {
                // if no grant type was provided, use the default
                grantType = OAuth2GrantType.AuthorizationCode;
            }
            else if (grantTypes.Count == 1 && grantTypes.Contains(OAuth2GrantType.AuthorizationCode))
            {
                grantType = OAuth2GrantType.AuthorizationCode;
            }
            else if (grantTypes.Count == 2 && grantTypes.Contains(OAuth2GrantType.AuthorizationCode) && grantTypes.Contains(OAuth2GrantType.RefreshToken))
            {
                grantType = OAuth2GrantType.AuthorizationCode;
                requestRefreshTokenGrantType = true;
            }
            else if (grantTypes.Count == 1 && grantTypes.Contains(OAuth2GrantType.Implicit))
            {
                grantType = OAuth2GrantType.Implicit;
            }
            else if (grantTypes.Count == 1 && grantTypes.Contains(OAuth2GrantType.Password))
            {
                grantType = OAuth2GrantType.Password;
            }
            else if (grantTypes.Count == 2 && grantTypes.Contains(OAuth2GrantType.Password) && grantTypes.Contains(OAuth2GrantType.RefreshToken))
            {
                grantType = OAuth2GrantType.Password;
                requestRefreshTokenGrantType = true;
            }
            else if (grantTypes.Count == 1 && grantTypes.Contains(OAuth2GrantType.ClientCredentials))
            {
                grantType = OAuth2GrantType.ClientCredentials;
            }
            else
            {
                throw new ArgumentException("grantTypes contains an " + (grantTypes.Count > 1 ? "invalid combination of grant types" : "invalid grant type") + ".", nameof(grantTypes));
            }

            // validate the grantType and tokenEndpointAuthMethod (and assign the corresponding responseType)
            OAuth2ResponseType? responseType = null;
            switch (grantType)
            {
                case OAuth2GrantType.AuthorizationCode:
                    responseType = OAuth2ResponseType.Code;
                    if (tokenEndpointAuthMethod != OAuth2TokenEndpointAuthMethod.ClientSecretBasic && tokenEndpointAuthMethod != OAuth2TokenEndpointAuthMethod.None)
                    {
                        throw new ArgumentException("A grantType does not support the requested tokenEndpointAuthMethod.", nameof(grantType));
                    }
                    break;
                case OAuth2GrantType.Implicit:
                    responseType = OAuth2ResponseType.Token;
                    if (tokenEndpointAuthMethod != OAuth2TokenEndpointAuthMethod.None)
                    {
                        throw new ArgumentException("A grantType does not support the requested tokenEndpointAuthMethod.", nameof(grantType));
                    }
                    break;
                case OAuth2GrantType.ClientCredentials:
                    responseType = null;
                    if (tokenEndpointAuthMethod != OAuth2TokenEndpointAuthMethod.ClientSecretBasic)
                    {
                        throw new ArgumentException("A grantType does not support the requested tokenEndpointAuthMethod.", nameof(grantType));
                    }
                    break;
                case OAuth2GrantType.Password:
                    responseType = null;
                    if (tokenEndpointAuthMethod != OAuth2TokenEndpointAuthMethod.ClientSecretBasic)
                    {
                        throw new ArgumentException("A grantType does not support the requested tokenEndpointAuthMethod.", nameof(grantType));
                    }
                    break;
            }

            // verify that, if grant types require redirect uris, our caller has included at least one redirectUri.
            switch (grantType)
            {
                case OAuth2GrantType.AuthorizationCode:
                case OAuth2GrantType.Implicit:
                    if (redirectUris == null || redirectUris.Count == 0)
                    {
                        throw new ArgumentException(grantType.ToString() + " requires redirectUris.", nameof(redirectUris));
                    }
                    break;
                default:
                    // no response URIs required.
                    break;
            }

            /* STEP 2: create our JSON request payload */
            RegisterClientRequest requestPayload = new RegisterClientRequest();
            requestPayload.software_id = softwareId;
            requestPayload.software_version = softwareVersion;
            if (redirectUris != null)
            {
                requestPayload.redirect_uris = redirectUris.ToArray();
            }
            // token endpoint auth method
            requestPayload.token_endpoint_auth_method = OAuth2Convert.ConvertTokenEndpointAuthMethodToString(tokenEndpointAuthMethod);
            // grant types
            if (requestRefreshTokenGrantType)
            {
                requestPayload.grant_types = new string[] { OAuth2Convert.ConvertGrantTypeToString(grantType), OAuth2Convert.ConvertGrantTypeToString(OAuth2GrantType.RefreshToken) };
            }
            else
            {
                requestPayload.grant_types = new string[] { OAuth2Convert.ConvertGrantTypeToString(grantType) };
            }
            // response types
            if (responseType != null)
            {
                requestPayload.response_types = new string[] { OAuth2Convert.ConvertResponseTypeToString(responseType.Value) };
            }
            // scopes
            if (scopes != null)
            {
                requestPayload.scope = String.Join(" ", scopes.ToArray());
            }
            //
            string jsonEncodedRequestPayload = JsonConvert.SerializeObject(requestPayload, Formatting.None,
                new JsonSerializerSettings() { NullValueHandling = NullValueHandling.Ignore });

            /* STEP 3: send our dynamic client registration request */
            try
            {
                using (HttpClient httpClient = new HttpClient())
                {
                    // create request
                    var requestMessage = new HttpRequestMessage(HttpMethod.Post, clientRegistrationEndpoint);
                    requestMessage.Content = new HttpStringContent(jsonEncodedRequestPayload, Windows.Storage.Streams.UnicodeEncoding.Utf8, "application/json");
                    requestMessage.Headers.Accept.Clear();
                    requestMessage.Headers.Accept.Add(new Windows.Web.Http.Headers.HttpMediaTypeWithQualityHeaderValue("application/json"));
                    if (initialAccessToken != null)
                    {
                        requestMessage.Headers.Authorization = new Windows.Web.Http.Headers.HttpCredentialsHeaderValue("Bearer", initialAccessToken);
                    }
                    // send request
                    HttpResponseMessage responseMessage = await httpClient.SendRequestAsync(requestMessage);

                    // process response
                    switch (responseMessage.StatusCode)
                    {
                        case HttpStatusCode.Created:
                            {
                                // client was registered; parse response
                                RegisterClientResponse responsePayload = JsonConvert.DeserializeObject<RegisterClientResponse>(await responseMessage.Content.ReadAsStringAsync());
                                if (responsePayload.client_id == null)
                                {
                                    throw new OAuth2ServerErrorException();
                                }
                                OAuth2Client client = new OAuth2Client();
                                // Id
                                client.Id = responsePayload.client_id;
                                // Secret
                                client.Secret = responsePayload.client_secret;
                                // IssuedAt
                                if (responsePayload.client_id_issued_at != null)
                                {
                                    client.IssuedAt = DateTimeOffset.FromUnixTimeSeconds(long.Parse(responsePayload.client_id_issued_at.Value.ToString()));
                                }
                                // ExpiresAt
                                if (responsePayload.client_secret_expires_at != null && responsePayload.client_secret_expires_at != 0)
                                {
                                    client.SecretExpiresAt = DateTimeOffset.FromUnixTimeSeconds(long.Parse(responsePayload.client_secret_expires_at.Value.ToString()));
                                }
                                // SoftwareId
                                client.SoftwareId = responsePayload.software_id;
                                // SoftwareVersion
                                client.SoftwareVersion = responsePayload.software_version;
                                // RedirectUris
                                if (responsePayload.redirect_uris != null)
                                {
                                    client.RedirectUris = responsePayload.redirect_uris.ToList<string>();
                                }
                                // TokenEndpointAuthMethod
                                if (responsePayload.token_endpoint_auth_method != null)
                                {
                                    OAuth2TokenEndpointAuthMethod? allowedTokenEndpointAuthMethod = OAuth2Convert.ConvertStringToTokenEndpointAuthMethod(responsePayload.token_endpoint_auth_method);
                                    if (allowedTokenEndpointAuthMethod != null)
                                    {
                                        client.TokenEndpointAuthMethod = allowedTokenEndpointAuthMethod.Value;
                                    }
                                }
                                // GrantTypes
                                if (responsePayload.grant_types != null)
                                {
                                    client.GrantTypes = new List<OAuth2.OAuth2GrantType>();
                                    foreach (string grantTypeAsString in responsePayload.grant_types)
                                    {
                                        OAuth2GrantType? allowedGrantType = OAuth2Convert.ConvertStringToGrantType(grantTypeAsString);
                                        if (allowedGrantType != null)
                                        {
                                            client.GrantTypes.Add(allowedGrantType.Value);
                                        }
                                    }
                                }
                                // Scope
                                client.Scope = responsePayload.scope;
                                // RegistrationAccessToken and RegistrationAccessUri
                                if (responsePayload.registration_access_token != null && responsePayload.registration_client_uri != null)
                                {
                                    // RegistrationAccessToken
                                    client.RegistrationToken = responsePayload.registration_access_token;
                                    // RegistrationAccessUri
                                    client.RegistrationUri = responsePayload.registration_client_uri;
                                }
                                // return our client
                                return client;
                            }
                        case HttpStatusCode.BadRequest:
                            {
                                // process the "bad request" response
                                OAuth2ErrorResponse responsePayload = JsonConvert.DeserializeObject<OAuth2ErrorResponse>(await responseMessage.Content.ReadAsStringAsync());
                                if (responsePayload.error == null)
                                {
                                    throw new OAuth2ServerErrorException();
                                }

                                switch (responsePayload.error.ToLowerInvariant())
                                {
                                    case "invalid_redirect_uri":
                                        throw new ArgumentException(responsePayload.error_description ?? responsePayload.error, nameof(redirectUris));
                                    case "invalid_client_metadata":
                                        throw new ArgumentException(responsePayload.error_description ?? responsePayload.error);
                                    default:
                                        throw new OAuth2HttpException(responseMessage.StatusCode);
                                }
                            }
                        case HttpStatusCode.PaymentRequired:
                            throw new OAuth2PaymentRequiredException();
                        case HttpStatusCode.Forbidden:
                            throw new OAuth2ForbiddenException();
                        case HttpStatusCode.TooManyRequests:
                            throw new OAuth2TooManyRequestsException();
                        case HttpStatusCode.InternalServerError:
                            throw new OAuth2ServerErrorException();
                        case HttpStatusCode.ServiceUnavailable:
                            throw new OAuth2ServiceUnavailableException();
                        default:
                            throw new OAuth2HttpException(responseMessage.StatusCode);
                    }
                }
            }
            catch (JsonException)
            {
                // JSON parsing error; this is catastrophic.
                throw new OAuth2ServerErrorException();
            }
            catch
            {
                // NOTE: callers must catch non-HTTP networking exceptions
                throw;
            }
        }

        #endregion

        #region "Token Endpoint"

        private struct RequestTokenResponse
        {
            public string access_token;
            public string token_type;
            public long? expires_in;
            public string refresh_token;
            public string scope;
        }
        public async Task<OAuth2Token> RequestTokenAsync(Uri tokenEndpoint, string authorizationCode, string redirectUri)
        {
            /* STEP 1: validate all arguments */

            // validate our tokenEndpoint uri
            if (tokenEndpoint == null)
            {
                throw new ArgumentNullException(nameof(tokenEndpoint));
            }
            else if (tokenEndpoint.Scheme.ToLowerInvariant() != "https")
            {
                throw new ArgumentException("tokenEndpoint must be secured with the https protocol.", nameof(tokenEndpoint));
            }

            if (authorizationCode == null)
            {
                throw new ArgumentNullException(nameof(authorizationCode));
            }

            /* validate redirectUri: make sure that the redirectUri uses HTTPS or a non-HTTP protocol (e.g. an app-specific protocol on a mobile 
             * device).  HTTP is also valid with a redirectUri--but only for the localhost. */
            if (redirectUri != null)
            {
                // break the redirectUri down into its components (scheme, host, etc.)
                Uri uri;
                try
                {
                    uri = new Uri(redirectUri);
                }
                catch
                {
                    throw new ArgumentException("redirectUri is a malformed redirect uri.", nameof(redirectUri));
                }
                //
                if (uri.Host == null)
                {
                    throw new ArgumentException("redirectUri is a malformed redirect uri.", nameof(redirectUri));
                }
                //
                switch (uri.Scheme.ToLowerInvariant())
                {
                    case "http":
                        // HTTP scheme is okay as long as the server is localhost (i.e. communication is on the loopback interface).
                        if (uri.Host != "127.0.0.1" && uri.Host != "::1" && uri.Host.ToLowerInvariant() != "localhost")
                            throw new ArgumentException("redirectUri must be secured with the https protocol.", nameof(redirectUri));
                        break;
                    case "https":
                        // HTTPS scheme is okay
                        break;
                    default:
                        // custom app-specific schemes are okay
                        break;
                }
            }

            /* STEP 2: create our WwwFormUrlencoded request payload */
            Dictionary<string, string> formParameters = new Dictionary<string, string>();
            formParameters["grant_type"] = OAuth2Convert.ConvertGrantTypeToString(OAuth2GrantType.AuthorizationCode);
            formParameters["code"] = authorizationCode;
            if (redirectUri != null)
            {
                formParameters["redirect_uri"] = redirectUri;
            }
            // if we have a client secret, we will authenticate via HTTP BASIC auth; otherwise, pass in our client_id as a form paramter
            if (this.Secret == null)
            {
                formParameters["client_id"] = this.Id;
            }

            /* STEP 3: send our access token request */
            try
            {
                using (HttpClient httpClient = new HttpClient())
                {
                    // create request
                    var requestMessage = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint);
                    requestMessage.Content = new HttpFormUrlEncodedContent(formParameters);
                    requestMessage.Headers.Accept.Clear();
                    requestMessage.Headers.Accept.Add(new Windows.Web.Http.Headers.HttpMediaTypeWithQualityHeaderValue("application/json"));
                    // if we have a client secret, add our client_id and client_secret to authenticate via HTTP Basic authentication
                    if (this.Secret != null)
                    {
                        string authorizationCredentialString = this.Id + ":" + this.Secret;
                        requestMessage.Headers.Authorization = new Windows.Web.Http.Headers.HttpCredentialsHeaderValue("Basic", Convert.ToBase64String(System.Text.Encoding.ASCII.GetBytes(authorizationCredentialString)));
                    }
                    // send request
                    HttpResponseMessage responseMessage = await httpClient.SendRequestAsync(requestMessage);

                    // process response
                    switch (responseMessage.StatusCode)
                    {
                        case HttpStatusCode.Ok:
                            {
                                // token was requested; parse response
                                RequestTokenResponse responsePayload = JsonConvert.DeserializeObject<RequestTokenResponse>(await responseMessage.Content.ReadAsStringAsync());
                                if (responsePayload.token_type.ToLowerInvariant() != "bearer")
                                {
                                    throw new OAuth2ServerErrorException();
                                }
                                OAuth2Token token = new OAuth2Token()
                                {
                                    Id = responsePayload.access_token
                                };
                                if (responsePayload.expires_in != null)
                                {
                                    token.ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(long.Parse(responsePayload.expires_in.Value.ToString()));
                                }
                                //if (responsePayload.refresh_token != null)
                                //{
                                //    token.RefreshTokenId = responsePayload.refresh_token;
                                //}
                                //if (responsePayload.scope != null)
                                //{
                                //    token.Scope = responsePayload.scope;
                                //}
                                return token;
                            }
                        case HttpStatusCode.BadRequest:
                            {
                                // process the "bad request" response
                                OAuth2ErrorResponse responsePayload = JsonConvert.DeserializeObject<OAuth2ErrorResponse>(await responseMessage.Content.ReadAsStringAsync());
                                if (responsePayload.error == null)
                                {
                                    throw new OAuth2ServerErrorException();
                                }

                                switch (responsePayload.error.ToLowerInvariant())
                                {
                                    case "invalid_request":
                                        throw new ArgumentException(responsePayload.error_description ?? responsePayload.error);
                                    case "invalid_client":
                                        throw new OAuth2InvalidClientException(responsePayload.error_description ?? responsePayload.error);
                                    case "invalid_grant":
                                        throw new ArgumentException(responsePayload.error_description ?? responsePayload.error, nameof(authorizationCode));
                                    case "unauthorized_client":
                                        throw new OAuth2UnauthorizedClientException(responsePayload.error_description ?? responsePayload.error);
                                    //case "unsupported_grant_type":
                                    //    // NOTE: this error should never occur when requesting a token via authorization_code
                                    //case "invalid_scope":
                                    //    // NOTE: this error should never occur when requesting a token via authorization_code
                                    default:
                                        throw new OAuth2HttpException(responseMessage.StatusCode);
                                }
                            }
                        case HttpStatusCode.TooManyRequests:
                            throw new OAuth2TooManyRequestsException();
                        case HttpStatusCode.InternalServerError:
                            throw new OAuth2ServerErrorException();
                        case HttpStatusCode.ServiceUnavailable:
                            throw new OAuth2ServiceUnavailableException();
                        default:
                            throw new OAuth2HttpException(responseMessage.StatusCode);
                    }
                }
            }
            catch (JsonException)
            {
                // JSON parsing error; this is catastrophic.
                throw new OAuth2ServerErrorException();
            }
            catch
            {
                // NOTE: callers must catch non-HTTP networking exceptions
                throw;
            }
        }

        #endregion

        #region "Parsing Helpers"

        const string _alphaNumericCharactersAsString = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        const string _allowedScopeSpecialCharactersAsString = "-_";

        static bool ContainsOnlyAllowedScopeCharacters(string stringToTest)
        {
            string validCharsAsString = _alphaNumericCharactersAsString + _allowedScopeSpecialCharactersAsString;
            char[] validChars = validCharsAsString.ToCharArray();
            foreach (char c in stringToTest)
            {
                if (!validChars.Contains(c))
                    return false;
            }

            // if all characters passed, return true.
            return true;
        }
        
        #endregion
    }
}
