using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.Web.Http;

namespace Strombus.OAuth2
{
    public abstract class OAuth2Exception : Exception
    {
        public OAuth2Exception() : base() { }
        public OAuth2Exception(string message) : base(message) { }
        public OAuth2Exception(string message, Exception innerException) : base(message, innerException) { }
    }

    /* invalid client exception (used by token endpoint) */
    public class OAuth2InvalidClientException: OAuth2Exception
    {
        public OAuth2InvalidClientException() { }
        public OAuth2InvalidClientException(string message) : base(message) { }
    }

    /* unauthorized client exception (used by token endpoint) */
    public class OAuth2UnauthorizedClientException : OAuth2Exception
    {
        public OAuth2UnauthorizedClientException() { }
        public OAuth2UnauthorizedClientException(string message) : base(message) { }
    }

    /* (base) generic http exception */
    public class OAuth2HttpException : OAuth2Exception
    {
        public HttpStatusCode StatusCode { private set; get; }

        public OAuth2HttpException(HttpStatusCode statusCode)
        {
            this.StatusCode = statusCode;
        }
        //public OAuth2HttpException(HttpStatusCode statusCode, string message) : base(message) 
        //{ 
        //    this.StatusCode = statusCode;
        //}
    }

    /* HTTP 402 error */
    public class OAuth2PaymentRequiredException : OAuth2HttpException
    {
        public OAuth2PaymentRequiredException() : base(HttpStatusCode.PaymentRequired) { }
        //public OAuth2PaymentRequiredException(string message) : base(message) { }
    }

    /* HTTP 403 error */
    public class OAuth2ForbiddenException : OAuth2HttpException
    {
        public OAuth2ForbiddenException() : base(HttpStatusCode.Forbidden) { }
        //public OAuth2ForbiddenException(string message) : base(message) { }
    }

    /* HTTP 429 error */
    public class OAuth2TooManyRequestsException : OAuth2HttpException
    {
        public OAuth2TooManyRequestsException() : base(HttpStatusCode.TooManyRequests) { }
        //public OAuth2TooManyRequestsException(string message) : base(message) { }
    }

    /* HTTP 500 error (and also returned in case of other server failures, as a generic server error) */
    public class OAuth2ServerErrorException : OAuth2HttpException
    {
        public OAuth2ServerErrorException() : base(HttpStatusCode.InternalServerError) { }
        //public OAuth2ServerErrorException(string message) : base(message) { }
    }

    /* HTTP 503 error */
    public class OAuth2ServiceUnavailableException : OAuth2HttpException
    {
        public OAuth2ServiceUnavailableException() : base(HttpStatusCode.ServiceUnavailable) { }
        //public OAuth2ServiceUnavailableException(string message) : base(message) { }
    }
}
