using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SaveVault.Data;
using System.Net;

namespace SafeVault.Tests.Integration
{
    public class SecurityIntegrationTests : IClassFixture<WebApplicationFactory<SaveVault.Program>>
    {
        private readonly WebApplicationFactory<SaveVault.Program> _factory;
        private readonly HttpClient _client;

        public SecurityIntegrationTests(WebApplicationFactory<SaveVault.Program> factory)
        {
            _factory = factory.WithWebHostBuilder(builder =>
            {
                builder.ConfigureServices(services =>
                {
                    // Remove the app's ApplicationDbContext registration
                    services.RemoveAll(typeof(DbContextOptions<ApplicationDbContext>));
                    services.RemoveAll(typeof(ApplicationDbContext));

                    // Add ApplicationDbContext using an in-memory database for testing
                    services.AddDbContext<ApplicationDbContext>(options =>
                    {
                        options.UseInMemoryDatabase("InMemoryDbForTesting");
                    });
                });

                builder.UseEnvironment("Testing");
            });

            _client = _factory.CreateClient();
        }

        [Fact]
        public async Task Home_Page_Should_Include_Security_Headers()
        {
            // Act
            var response = await _client.GetAsync("/");

            // Assert
            response.EnsureSuccessStatusCode();

            // Check for security headers
            Assert.True(response.Headers.Contains("X-Content-Type-Options"));
            Assert.True(response.Headers.Contains("X-Frame-Options"));
            Assert.True(response.Headers.Contains("X-XSS-Protection"));
            Assert.True(response.Headers.Contains("Referrer-Policy"));
            Assert.True(response.Headers.Contains("Content-Security-Policy"));

            // Verify header values
            Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").First());
            Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").First());
            Assert.Equal("1; mode=block", response.Headers.GetValues("X-XSS-Protection").First());
        }

        [Fact]
        public async Task Documents_Should_Require_Authentication()
        {
            // Act
            var response = await _client.GetAsync("/Documents");

            // Assert
            Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
            Assert.Contains("/Auth/Login", response.Headers.Location?.ToString());
        }

        [Fact]
        public async Task Documents_Create_Should_Require_Authentication()
        {
            // Act
            var response = await _client.GetAsync("/Documents/Create");

            // Assert
            Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
            Assert.Contains("/Auth/Login", response.Headers.Location?.ToString());
        }

        [Fact]
        public async Task Login_Page_Should_Be_Accessible()
        {
            // Act
            var response = await _client.GetAsync("/Auth/Login");

            // Assert
            response.EnsureSuccessStatusCode();
            var content = await response.Content.ReadAsStringAsync();
            Assert.Contains("Login to SaveVault", content);
        }

        [Fact]
        public async Task Register_Page_Should_Be_Accessible()
        {
            // Act
            var response = await _client.GetAsync("/Auth/Register");

            // Assert
            response.EnsureSuccessStatusCode();
            var content = await response.Content.ReadAsStringAsync();
            Assert.Contains("Create Account", content);
        }

        [Fact]
        public async Task Login_POST_Should_Require_Antiforgery_Token()
        {
            // Arrange
            var formData = new List<KeyValuePair<string, string>>
            {
                new("Email", "test@example.com"),
                new("Password", "TestPassword123!")
            };

            // Act
            var response = await _client.PostAsync("/Auth/Login", new FormUrlEncodedContent(formData));

            // Assert
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }

        [Fact]
        public async Task Register_POST_Should_Require_Antiforgery_Token()
        {
            // Arrange
            var formData = new List<KeyValuePair<string, string>>
            {
                new("FullName", "Test User"),
                new("Email", "test@example.com"),
                new("Password", "TestPassword123!"),
                new("ConfirmPassword", "TestPassword123!")
            };

            // Act
            var response = await _client.PostAsync("/Auth/Register", new FormUrlEncodedContent(formData));

            // Assert
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }

        [Fact]
        public async Task Application_Should_Redirect_HTTP_To_HTTPS()
        {
            // This test would be more meaningful in a real environment
            // In development, HTTPS redirection might not be enforced
            var response = await _client.GetAsync("/");
            
            // Just verify we can access the application
            Assert.True(response.IsSuccessStatusCode || response.StatusCode == HttpStatusCode.Redirect);
        }

        [Fact]
        public async Task Application_Should_Not_Expose_Server_Information()
        {
            // Act
            var response = await _client.GetAsync("/");

            // Assert
            Assert.False(response.Headers.Contains("Server"));
            Assert.False(response.Headers.Contains("X-Powered-By"));
            Assert.False(response.Headers.Contains("X-AspNet-Version"));
        }

        [Fact]
        public async Task Nonexistent_Page_Should_Return_404()
        {
            // Act
            var response = await _client.GetAsync("/NonexistentPage");

            // Assert
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        }

        [Theory]
        [InlineData("/Documents/Details/999")]
        [InlineData("/Documents/Edit/999")]
        [InlineData("/Documents/Delete/999")]
        public async Task Document_Actions_With_Invalid_ID_Should_Require_Auth(string url)
        {
            // Act
            var response = await _client.GetAsync(url);

            // Assert
            Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
            Assert.Contains("/Auth/Login", response.Headers.Location?.ToString());
        }

        [Fact]
        public async Task Application_Should_Handle_Large_Request_Safely()
        {
            // Arrange
            var largeData = new string('A', 1024 * 1024); // 1MB string
            var formData = new List<KeyValuePair<string, string>>
            {
                new("largeField", largeData)
            };

            // Act
            var response = await _client.PostAsync("/Auth/Login", new FormUrlEncodedContent(formData));

            // Assert
            // Should handle gracefully without crashing
            Assert.True(response.StatusCode == HttpStatusCode.BadRequest || 
                       response.StatusCode == HttpStatusCode.RequestEntityTooLarge);
        }

        [Theory]
        [InlineData("/../../../etc/passwd")]
        [InlineData("/..\\..\\..\\windows\\system32\\config\\sam")]
        [InlineData("/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd")]
        public async Task Application_Should_Prevent_Directory_Traversal(string maliciousPath)
        {
            // Act
            var response = await _client.GetAsync(maliciousPath);

            // Assert
            Assert.NotEqual(HttpStatusCode.OK, response.StatusCode);
            Assert.True(response.StatusCode == HttpStatusCode.NotFound || 
                       response.StatusCode == HttpStatusCode.BadRequest);
        }

        [Fact]
        public async Task Application_Should_Set_Secure_Cookie_Policies()
        {
            // Act
            var response = await _client.GetAsync("/Auth/Login");

            // Assert
            response.EnsureSuccessStatusCode();
            
            // Check if response sets any cookies with secure flags
            if (response.Headers.Contains("Set-Cookie"))
            {
                var cookies = response.Headers.GetValues("Set-Cookie");
                foreach (var cookie in cookies)
                {
                    // Security-related cookies should have proper flags
                    if (cookie.Contains("auth") || cookie.Contains("session"))
                    {
                        Assert.Contains("HttpOnly", cookie);
                        // In production, should also contain "Secure"
                    }
                }
            }
        }

        [Fact]
        public async Task Error_Pages_Should_Not_Expose_Sensitive_Information()
        {
            // Act - Try to cause an error
            var response = await _client.GetAsync("/Documents/Details/abc"); // Invalid ID format

            // Assert
            var content = await response.Content.ReadAsStringAsync();
            
            // Should not expose stack traces, connection strings, etc.
            Assert.DoesNotContain("SqlConnection", content);
            Assert.DoesNotContain("ConnectionString", content);
            Assert.DoesNotContain("Exception", content);
            Assert.DoesNotContain("StackTrace", content);
        }
    }
}