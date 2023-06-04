using Microsoft.AspNetCore.Authentication.OAuth;
using oAuth_2._0.Interface;
using System.Security.Claims;

namespace oAuth_2._0.Service
{
    public class OAuthService : IOAuthService
    {
        private readonly IConfiguration _configuration;

        public OAuthService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public async Task<OAuthAuthenticationOptions> GetOAuthOptions()
        {
            string clientId = _configuration["OAuth:ClientId"];
            string clientSecret = _configuration["OAuth:ClientSecret"];
            string tokenEndpoint = _configuration["OAuth:TokenEndpoint"];
            string scope = _configuration["OAuth:Scope"];

            var authProperties = new OAuthAuthenticationOptions()
            {
                ClientId = clientId,
                ClientSecret = clientSecret,
                CallbackPath = "/signin-oidc",
                AuthorizationEndpoint = "https://cobankasabı.com/oauth/authorize",
                TokenEndpoint = tokenEndpoint,
                Scope = scope,
                SaveTokens = true,
                Events = new OAuthEvents
                {
                    OnCreatingTicket = async context =>
                    {
                        var accessToken = context.AccessToken;
                        var identity = (ClaimsIdentity)context.Principal.Identity;
                        identity.AddClaim(new Claim("access_token", accessToken));
                    }
                }
            };

            return authProperties;
        }
    }
}
