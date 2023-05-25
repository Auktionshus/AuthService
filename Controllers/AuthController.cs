using System.Text;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using MongoDB.Driver;
using System.Net.Http;
using System.Net.Http.Headers;
using Newtonsoft.Json;
using System.Net.Http;

namespace AuthService.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly ILogger<AuthController> _logger;
        private readonly string _hostName;
        private readonly string _secret;
        private readonly string _issuer;
        private readonly string _mongoDbConnectionString;
        private readonly HttpClient _httpClient;

        public AuthController(
            ILogger<AuthController> logger,
            IConfiguration config,
            IHttpClientFactory clientFactory
        )
        {
            _mongoDbConnectionString = config["MongoDbConnectionString"];
            _hostName = config["HostnameRabbit"];
            _secret = config["Secret"];
            _issuer = config["Issuer"];

            _logger = logger;
            _logger.LogInformation($"Connection: {_hostName}");
        }

        private string GenerateJwtToken(string username)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secret));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var claims = new[] { new Claim(ClaimTypes.NameIdentifier, username) };
            var token = new JwtSecurityToken(
                _issuer,
                "http://localhost",
                claims,
                expires: DateTime.Now.AddMinutes(15),
                signingCredentials: credentials
            );
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] RegisterModel model)
        {
            MongoClient dbClient = new MongoClient(_mongoDbConnectionString);
            var collection = dbClient.GetDatabase("user").GetCollection<User>("users");

            User user = await collection
                .Find<User>(u => u.Email == model.Email)
                .FirstOrDefaultAsync();

            if (user == null)
            {
                return BadRequest(new { message = "Email or password is incorrect" });
            }
            else if (!VerifyPasswordHash(model.Password, user.PasswordHash, user.PasswordSalt))
            {
                return BadRequest(new { message = "Email or password is incorrect" });
            }

            var loginModel = new { Username = model.Email, Password = model.Password };
            var content = new StringContent(
                JsonConvert.SerializeObject(loginModel),
                Encoding.UTF8,
                "application/json"
            );
            var response = await _httpClient.PostAsync("http://localhost:8000/auth/login", content);

            if (response.IsSuccessStatusCode)
            {
                var responseContent = await response.Content.ReadAsStringAsync();
                var token = JsonConvert.DeserializeObject<dynamic>(responseContent).token;
                return Ok(
                    new
                    {
                        Id = user.Id,
                        Email = user.Email,
                        FirstName = user.FirstName,
                        LastName = user.LastName,
                        Token = token
                    }
                );
            }

            return BadRequest(new { message = "Could not generate token" });
        }

        [AllowAnonymous]
        [HttpPost("validate")]
        public async Task<IActionResult> ValidateJwtToken([FromBody] string token)
        {
            if (string.IsNullOrEmpty(token))
            {
                return BadRequest("Invalid token submitted.");
            }

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_secret);

            try
            {
                tokenHandler.ValidateToken(
                    token,
                    new TokenValidationParameters
                    {
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = new SymmetricSecurityKey(key),
                        ValidateIssuer = false,
                        ValidateAudience = false,
                        ClockSkew = TimeSpan.Zero
                    },
                    out SecurityToken validatedToken
                );

                var jwtToken = (JwtSecurityToken)validatedToken;
                var accountId = jwtToken.Claims
                    .First(x => x.Type == ClaimTypes.NameIdentifier)
                    .Value;
                return Ok(accountId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, ex.Message);
                return StatusCode(404);
            }
        }

        private void CreatePasswordHash(
            string password,
            out byte[] passwordHash,
            out byte[] passwordSalt
        )
        {
            using (var hmac = new System.Security.Cryptography.HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPasswordHash(string password, byte[] storedHash, byte[] storedSalt)
        {
            if (password == null)
                throw new ArgumentNullException(nameof(password));
            if (string.IsNullOrWhiteSpace(password))
                throw new ArgumentException(
                    "Value cannot be empty or whitespace only string.",
                    nameof(password)
                );
            if (storedHash.Length != 64)
                throw new ArgumentException(
                    "Invalid length of password hash (64 bytes expected).",
                    nameof(storedHash)
                );
            if (storedSalt.Length != 128)
                throw new ArgumentException(
                    "Invalid length of password salt (128 bytes expected).",
                    nameof(storedSalt)
                );

            using (var hmac = new System.Security.Cryptography.HMACSHA512(storedSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                for (int i = 0; i < computedHash.Length; i++)
                {
                    if (computedHash[i] != storedHash[i])
                        return false;
                }
            }

            return true;
        }
    }
}



/*/
using System.Text;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using MongoDB.Driver;
using System.Net.Http;
using System.Net.Http.Headers;
using Newtonsoft.Json;

namespace AuthService.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthController : ControllerBase
{
    private readonly ILogger<AuthController> _logger;
    private readonly string _hostName;
    private readonly string _secret;
    private readonly string _issuer;

    public AuthController(ILogger<AuthController> logger, IConfiguration config)
    {
        _hostName = config["HostnameRabbit"];
        _secret = config["Seceret"];
        _issuer = config["Issuer"];

        _logger = logger;
        _logger.LogInformation($"Connection: {_hostName}");
    }

    private string GenerateJwtToken(string username)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secret));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
        var claims = new[] { new Claim(ClaimTypes.NameIdentifier, username) };
        var token = new JwtSecurityToken(
            _issuer,
            "http://localhost",
            claims,
            expires: DateTime.Now.AddMinutes(15),
            signingCredentials: credentials
        );
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public class LoginModel
    {
        public string? Username { get; set; }
        public string? Password { get; set; }
    }


    [AllowAnonymous]
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginModel login)
    {
        if (login.Username != "username" || login.Password != "password")
        {
            return Unauthorized();
        }
        var token = GenerateJwtToken(login.Username);
        return Ok(new { token });
    }


     [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] RegisterModel model)
        {
            var user = await _users.Find<User>(u => u.Email == model.Email).FirstOrDefaultAsync();

            if (user == null)
            {
                return BadRequest(new { message = "Email or password is incorrect" });
            }

            if (!VerifyPasswordHash(model.Password, user.PasswordHash, user.PasswordSalt))
            {
                return BadRequest(new { message = "Email or password is incorrect" });
            }

            var loginModel = new { Username = model.Email, Password = model.Password };
            var content = new StringContent(JsonConvert.SerializeObject(loginModel), Encoding.UTF8, "application/json");
            var response = await _httpClient.PostAsync("http://localhost:8002/auth/login", content);

            if (response.IsSuccessStatusCode)
            {
                var responseContent = await response.Content.ReadAsStringAsync();
                var token = JsonConvert.DeserializeObject<dynamic>(responseContent).token;
                return Ok(new
                {
                    Id = user.Id,
                    Email = user.Email,
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    Token = token
                });
            }

            return BadRequest(new { message = "Could not generate token" });
        }

    [AllowAnonymous]
    [HttpPost("validate")]
    public async Task<IActionResult> ValidateJwtToken([FromBody] string? token)
    {
        if (token.IsNullOrEmpty())
            return BadRequest("Invalid token submited.");
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_secret!);
        try
        {
            tokenHandler.ValidateToken(
                token,
                new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ClockSkew = TimeSpan.Zero
                },
                out SecurityToken validatedToken
            );
            var jwtToken = (JwtSecurityToken)validatedToken;
            var accountId = jwtToken.Claims.First(x => x.Type == ClaimTypes.NameIdentifier).Value;
            return Ok(accountId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, ex.Message);
            return StatusCode(404);
        }
        
    }

    [Authorize]
    [HttpGet]
         public async Task<IActionResult> Get()
            {
                return Ok("You're authorized");
            }
}
/*/
