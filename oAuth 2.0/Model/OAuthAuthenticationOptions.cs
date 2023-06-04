using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;

public class OAuthAuthenticationOptions : AuthenticationProperties
{
    public string ClientId { get; set; }
    public string ClientSecret { get; set; }
    public string CallbackPath { get; set; }
    public string AuthorizationEndpoint { get; set; }
    public string TokenEndpoint { get; set; }
    public string Scope { get; set; }
    public bool SaveTokens { get; set; }
    public OAuthEvents Events { get; set; }
}