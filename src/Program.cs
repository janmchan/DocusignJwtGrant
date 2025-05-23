using DocusignAuthentication;
using Microsoft.Extensions.Configuration;

var configuration = new ConfigurationBuilder()
    .AddUserSecrets<Program>() 
    .Build();

const string TokenEndpoint = "https://account-d.docusign.com/oauth/token";
const string Audience = "account-d.docusign.com";

var parameters = new DocusignJwtParameters
{
    ClientId = configuration["ClientId"] ?? throw new Exception("ClientId secret missing"),
    UserId = configuration["UserId"] ?? throw new Exception("UserId secret missing"),
    PrivateKey = configuration["PrivateKey"] ?? throw new Exception("PrivateKey secret missing"), //include \r\n from PEM file
    TokenEndpoint = TokenEndpoint,
    Audience = Audience
};

string[] scopes = { "signature",
    "user_read",
    "user_write",
    "impersonation" }; 

try
{
    var jwtHelper = new DocuSignJwtHelper(parameters);
    string accessToken = await jwtHelper.FetchAccessTokenAsync(scopes);

    Console.WriteLine($"Successfully retrieved access token: {accessToken}");
}
catch (Exception ex)
{
    Console.WriteLine($"Error: {ex.Message}");
    if (ex.InnerException != null)
    {
        Console.WriteLine($"Inner Exception: {ex.InnerException.Message}");
    }
}