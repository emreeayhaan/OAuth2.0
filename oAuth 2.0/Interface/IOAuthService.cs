namespace oAuth_2._0.Interface
{
    public interface IOAuthService
    {
        Task<OAuthAuthenticationOptions> GetOAuthOptions();
    }
}
