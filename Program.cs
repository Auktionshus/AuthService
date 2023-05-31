using System.Text;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using NLog;
using NLog.Web;
using VaultSharp;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.Commons;

var logger = NLog.LogManager.Setup().LoadConfigurationFromAppSettings().GetCurrentClassLogger();
logger.Debug("init main");

try
{
    var EndPoint = "https://vault_dev:8201/";
    logger.Info($"EndPoint: {EndPoint}");
    var httpClientHandler = new HttpClientHandler();
    logger.Info("Before ServerCertificateCustomValidationCallback");
    httpClientHandler.ServerCertificateCustomValidationCallback = (
        message,
        cert,
        chain,
        sslPolicyErrors
    ) =>
    {
        logger.Info("Inside ServerCertificateCustomValidationCallback");
        return true;
    };
    logger.Info("After ServerCertificateCustomValidationCallback");

    // Initialize one of the several auth methods.
    IAuthMethodInfo authMethod = new TokenAuthMethodInfo("00000000-0000-0000-0000-000000000000");
    // Initialize settings. You can also set proxies, custom delegates etc. here.
    var vaultClientSettings = new VaultClientSettings(EndPoint, authMethod)
    {
        Namespace = "",
        MyHttpClientProviderFunc = handler =>
            new HttpClient(httpClientHandler) { BaseAddress = new Uri(EndPoint) }
    };
    IVaultClient vaultClient = new VaultClient(vaultClientSettings);
    logger.Info($"vault client created: {vaultClient}");
    // Use client to read a key-value secret.
    Secret<SecretData> kv2Secret = await vaultClient.V1.Secrets.KeyValue.V2.ReadSecretAsync(
        path: "JWT",
        mountPoint: "secret"
    );
    var secret = kv2Secret.Data.Data["Secret"];
    var issuer = kv2Secret.Data.Data["Issuer"];
    logger.Info($"Secret: {secret}");
    logger.Info($"Issuer: {issuer}");

    var builder = WebApplication.CreateBuilder(args);

    builder.Services
        .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
        .AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters()
            {
                ValidateIssuer = true,
                ValidateAudience = false,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = issuer,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret))
            };
        });

    // Add services to the container.

    builder.Services.AddControllers();

    // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen();

    // Configure NLog for Dependency injection
    builder.Logging.ClearProviders();
    builder.Host.UseNLog();

    var app = builder.Build();

    // Configure the HTTP request pipeline.
    if (app.Environment.IsDevelopment())
    {
        app.UseSwagger();
        app.UseSwaggerUI();
    }

    app.UseHttpsRedirection();

    app.UseAuthentication();
    app.UseAuthorization();

    app.MapControllers();

    app.Run();
}
catch (Exception ex)
{
    logger.Error(ex, "Stopped program because of exception");
    throw;
}
finally
{
    NLog.LogManager.Shutdown();
}
