namespace DocusignAuthentication;
internal class DocusignJwtParameters
{
    public string ClientId { get; set; }
    public string UserId { get; set; }
    public string PrivateKey { get; set; }
    public string TokenEndpoint { get; set; }
    public string Audience { get; set; }

}
