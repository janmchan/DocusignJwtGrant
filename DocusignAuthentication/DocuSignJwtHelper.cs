using Microsoft.IdentityModel.JsonWebTokens;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System.Security.Claims;

namespace DocusignAuthentication;
internal class DocuSignJwtHelper
{
    private readonly string _clientId;
    private readonly string _userId;
    private readonly string _privateKey;
    private readonly string _algorithm;
    private readonly string _tokenEndpoint;
    private readonly string _audience;
    public DocuSignJwtHelper(DocusignJwtParameters parameters, string securityAlgorithm = SecurityAlgorithms.RsaSha256)
    {
        _clientId = parameters.ClientId;
        _userId = parameters.UserId;
        _privateKey = parameters.PrivateKey;
        _algorithm = securityAlgorithm;
        _tokenEndpoint = parameters.TokenEndpoint;
        _audience = parameters.Audience;
    }

    public async Task<string> FetchAccessTokenAsync(string[] scopes)
    {
        string jwt = CreateJwt(scopes);
        return await RequestAccessTokenAsync(jwt);
    }

    private string CreateJwt(string[] scopes)
    {
        var securityKey = new RsaSecurityKey(CreateRSAKeyFromPem(_privateKey));
        var credentials = new SigningCredentials(securityKey, _algorithm);

        var expiresInHours = 1;

        SecurityTokenDescriptor securityTokenDescriptor = new SecurityTokenDescriptor
        {
            Expires = DateTime.UtcNow.AddHours(expiresInHours),
            IssuedAt = DateTime.UtcNow
        };
        securityTokenDescriptor.Subject = new ClaimsIdentity();
        securityTokenDescriptor.Subject.AddClaim(new Claim("scope", string.Join(" ", scopes)));
        securityTokenDescriptor.Subject.AddClaim(new Claim("aud", _audience));
        securityTokenDescriptor.Subject.AddClaim(new Claim("iss", _clientId));
        securityTokenDescriptor.Subject.AddClaim(new Claim("sub", _userId));
        securityTokenDescriptor.SigningCredentials = credentials;


        var handler = new JsonWebTokenHandler
        {
            SetDefaultTimesOnTokenCreation = false
        };
        return handler.CreateToken(securityTokenDescriptor);
    }

    private async Task<string> RequestAccessTokenAsync(string jwt)
    {
        using (var httpClient = new HttpClient())
        {
            var requestContent = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                {"grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"},
                {"assertion", jwt}
            });

            var response = await httpClient.PostAsync(_tokenEndpoint, requestContent);
            response.EnsureSuccessStatusCode(); // Throw exception if not successful

            var responseContent = await response.Content.ReadAsStringAsync();
            using (JsonDocument doc = JsonDocument.Parse(responseContent))
            {
                if (doc.RootElement.TryGetProperty("access_token", out var accessToken))
                {
                    return accessToken.GetString();
                }
                else if (doc.RootElement.TryGetProperty("error_description", out var errorDescription))
                {
                    throw new Exception($"Failed to retrieve access token: {errorDescription.GetString()}");
                }
                else
                {
                    throw new Exception($"Failed to retrieve access token. Response: {responseContent}");
                }
            }
        }
    }
    protected static RSA CreateRSAKeyFromPem(string key)
    {
        object obj = new PemReader(new StringReader(key)).ReadObject();
        RSA rSA = RSA.Create();
        if (obj is AsymmetricCipherKeyPair asymmetricCipherKeyPair)
        {
            RSAParameters parameters = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)asymmetricCipherKeyPair.Private);
            rSA.ImportParameters(parameters);
            return rSA;
        }

        if (obj is RsaKeyParameters rsaKey)
        {
            RSAParameters parameters2 = DotNetUtilities.ToRSAParameters(rsaKey);
            rSA.ImportParameters(parameters2);
            return rSA;
        }

        throw new Exception("Unexpected PEM type");
    }
}
