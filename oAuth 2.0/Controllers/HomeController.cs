using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Mvc;
using oAuth_2._0.Interface;
using System.Security.Claims;

public class HomeController : Controller
{
    private readonly IOAuthService _oauthService;

    public HomeController(IOAuthService oauthService)
    {
        _oauthService = oauthService;
    }

    public async Task<IActionResult> Index()
    {
        string clientId = "your-client-id";
        string clientSecret = "your-client-secret";
        string tokenEndpoint = "https://cobankasabı.com/oauth/token";
        string scope = "read write";

        await HttpContext.SignInAsync(new ClaimsPrincipal(), new AuthenticationProperties
        {
            RedirectUri = null
        });

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

        await HttpContext.ChallengeAsync("OAuth", authProperties);

        return View();
    }
}
