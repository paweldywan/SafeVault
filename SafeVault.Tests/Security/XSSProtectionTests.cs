using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using SaveVault.Data;
using SaveVault.Models;
using SaveVault.Services;

namespace SafeVault.Tests.Security
{
    public class XSSProtectionTests
    {
        private ApplicationDbContext GetInMemoryContext()
        {
            var options = new DbContextOptionsBuilder<ApplicationDbContext>()
                .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
                .Options;
            return new ApplicationDbContext(options);
        }

        [Theory]
        [InlineData("<script>alert('xss')</script>")]
        [InlineData("<img src=x onerror=alert('xss')>")]
        [InlineData("<svg onload=alert('xss')>")]
        [InlineData("</script><script>alert('xss')</script>")]
        [InlineData("<iframe src=javascript:alert('xss')></iframe>")]
        [InlineData("<object data=javascript:alert('xss')>")]
        public async Task DocumentService_Should_Encode_XSS_In_Title(string maliciousTitle)
        {
            // Arrange
            using var context = GetInMemoryContext();
            var logger = new Mock<ILogger<DocumentService>>();
            var service = new DocumentService(context, logger.Object);

            var document = new Document
            {
                Title = maliciousTitle,
                Content = "Safe content",
                UserId = "test-user"
            };

            // Act
            var result = await service.CreateDocumentAsync(document);

            // Assert
            Assert.NotNull(result);
            
            // Verify that the result is different from input (encoded)
            Assert.NotEqual(maliciousTitle, result.Title);
            
            // Verify that dangerous scripts are HTML encoded, not removed
            Assert.DoesNotContain("<script>", result.Title);
            
            // Verify HTML encoding occurred
            if (maliciousTitle.Contains("<script>"))
            {
                Assert.Contains("&lt;script&gt;", result.Title);
            }
        }

        [Theory]
        [InlineData("<script>document.cookie='stolen'</script>")]
        [InlineData("<<SCRIPT>alert('XSS')</SCRIPT>")]
        [InlineData("<script>window.location='http://evil.com'</script>")]
        [InlineData("<img src=\"x\" onerror=\"eval(atob('YWxlcnQoJ1hTUycpOw=='))\">")]
        [InlineData("<div onclick=\"alert('XSS')\">Click me</div>")]
        [InlineData("<style>@import 'javascript:alert(\"XSS\")';</style>")]
        [InlineData("<link rel=stylesheet href=javascript:alert('XSS')>")]
        public async Task DocumentService_Should_Encode_XSS_In_Content(string maliciousContent)
        {
            // Arrange
            using var context = GetInMemoryContext();
            var logger = new Mock<ILogger<DocumentService>>();
            var service = new DocumentService(context, logger.Object);

            var document = new Document
            {
                Title = "Safe title",
                Content = maliciousContent,
                UserId = "test-user"
            };

            // Act
            var result = await service.CreateDocumentAsync(document);

            // Assert
            Assert.NotNull(result);
            
            // Verify that the result is different from input (encoded)
            Assert.NotEqual(maliciousContent, result.Content);
            
            // Verify that dangerous scripts are encoded
            Assert.DoesNotContain("<script>", result.Content);
            
            // Verify HTML encoding occurred
            if (maliciousContent.Contains("<script>"))
            {
                Assert.Contains("&lt;script&gt;", result.Content);
            }
        }

        [Fact]
        public async Task DocumentService_Should_Preserve_Safe_HTML_Encoded()
        {
            // Arrange
            using var context = GetInMemoryContext();
            var logger = new Mock<ILogger<DocumentService>>();
            var service = new DocumentService(context, logger.Object);

            var document = new Document
            {
                Title = "Safe title with & ampersand",
                Content = "Content with <b>bold</b> and \"quotes\"",
                UserId = "test-user"
            };

            // Act
            var result = await service.CreateDocumentAsync(document);

            // Assert
            Assert.NotNull(result);
            
            // Verify that safe content is properly encoded
            Assert.Contains("&amp;", result.Title); // & should be encoded
            Assert.Contains("&lt;b&gt;", result.Content); // < and > should be encoded
            Assert.Contains("&quot;", result.Content); // " should be encoded
        }

        [Fact]
        public async Task UpdateDocument_Should_Encode_XSS_Attacks()
        {
            // Arrange
            using var context = GetInMemoryContext();
            var logger = new Mock<ILogger<DocumentService>>();
            var service = new DocumentService(context, logger.Object);

            // Create initial document
            var initialDoc = new Document
            {
                Title = "Original Title",
                Content = "Original content",
                UserId = "test-user"
            };
            var created = await service.CreateDocumentAsync(initialDoc);

            // Update with malicious content
            var maliciousUpdate = new Document
            {
                Id = created.Id,
                Title = "<script>alert('XSS in update')</script>",
                Content = "<iframe src=javascript:alert('XSS')></iframe>",
                UserId = "test-user"
            };

            // Act
            var result = await service.UpdateDocumentAsync(maliciousUpdate);

            // Assert
            Assert.NotNull(result);
            Assert.DoesNotContain("<script>", result.Title);
            Assert.DoesNotContain("<iframe", result.Content);
            
            // Verify encoding occurred
            Assert.Contains("&lt;script&gt;", result.Title);
            Assert.Contains("&lt;iframe", result.Content);
        }

        [Theory]
        [InlineData("Data:\"/><script>alert('XSS')</script>")]
        [InlineData("vbscript:alert('XSS')")]
        [InlineData("livescript:alert('XSS')")]
        [InlineData("mocha:alert('XSS')")]
        [InlineData("charset=javascript:alert('XSS')")]
        public async Task DocumentService_Should_Encode_Protocol_Based_XSS(string maliciousInput)
        {
            // Arrange
            using var context = GetInMemoryContext();
            var logger = new Mock<ILogger<DocumentService>>();
            var service = new DocumentService(context, logger.Object);

            var document = new Document
            {
                Title = maliciousInput,
                Content = "Safe content",
                UserId = "test-user"
            };

            // Act
            var result = await service.CreateDocumentAsync(document);

            // Assert
            Assert.NotNull(result);
            
            // The content should be HTML encoded, making it safe
            Assert.NotEqual(maliciousInput, result.Title); // Should be different due to encoding
        }

        [Fact]
        public async Task DocumentService_Should_Handle_Multiple_XSS_Vectors()
        {
            // Arrange
            using var context = GetInMemoryContext();
            var logger = new Mock<ILogger<DocumentService>>();
            var service = new DocumentService(context, logger.Object);

            var document = new Document
            {
                Title = "<script>alert('1')</script><img src=x onerror=alert('2')>",
                Content = "<iframe src=javascript:alert('3')></iframe><svg onload=alert('4')>",
                UserId = "test-user"
            };

            // Act
            var result = await service.CreateDocumentAsync(document);

            // Assert
            Assert.NotNull(result);
            
            // Verify all XSS vectors are neutralized through encoding
            Assert.DoesNotContain("<script>", result.Title);
            Assert.DoesNotContain("<iframe", result.Content);
            Assert.DoesNotContain("<svg", result.Content);
            
            // Verify proper encoding
            Assert.Contains("&lt;script&gt;", result.Title);
            Assert.Contains("&lt;iframe", result.Content);
        }

        [Fact]
        public async Task DocumentService_Should_Handle_Empty_Input_Safely()
        {
            // Arrange
            using var context = GetInMemoryContext();
            var logger = new Mock<ILogger<DocumentService>>();
            var service = new DocumentService(context, logger.Object);

            var document = new Document
            {
                Title = "Valid Title", // Must be valid to pass validation
                Content = string.Empty,
                UserId = "test-user"
            };

            // Act
            var result = await service.CreateDocumentAsync(document);

            // Assert - Should work with empty content
            Assert.NotNull(result);
            Assert.Equal("Valid Title", result.Title);
            Assert.Equal(string.Empty, result.Content);
        }

        [Theory]
        [InlineData("Normal text content")]
        [InlineData("Text with numbers 12345")]
        [InlineData("Text with symbols !@#$%^&*()")]
        [InlineData("Multi-line\ncontent\nwith\nbreaks")]
        [InlineData("Unicode content: йснцdл")]
        public async Task DocumentService_Should_Preserve_Legitimate_Content(string legitimateContent)
        {
            // Arrange
            using var context = GetInMemoryContext();
            var logger = new Mock<ILogger<DocumentService>>();
            var service = new DocumentService(context, logger.Object);

            var document = new Document
            {
                Title = "Legitimate Title",
                Content = legitimateContent,
                UserId = "test-user"
            };

            // Act
            var result = await service.CreateDocumentAsync(document);

            // Assert
            Assert.NotNull(result);
            Assert.Equal("Legitimate Title", result.Title);
            
            // Content should be present but HTML encoded if it contains special chars
            Assert.NotEmpty(result.Content);
            if (legitimateContent.Contains("&"))
            {
                Assert.Contains("&amp;", result.Content);
            }
        }

        [Fact]
        public async Task DocumentService_Should_Encode_Special_Characters()
        {
            // Arrange
            using var context = GetInMemoryContext();
            var logger = new Mock<ILogger<DocumentService>>();
            var service = new DocumentService(context, logger.Object);

            var document = new Document
            {
                Title = "Title with <, >, &, \" and ' characters",
                Content = "Content with <script>, quotes \" and ' characters",
                UserId = "test-user"
            };

            // Act
            var result = await service.CreateDocumentAsync(document);

            // Assert
            Assert.NotNull(result);
            
            // Verify all special characters are encoded
            Assert.Contains("&lt;", result.Title);
            Assert.Contains("&gt;", result.Title);
            Assert.Contains("&amp;", result.Title);
            Assert.Contains("&quot;", result.Title);
            Assert.Contains("&#39;", result.Title);
            
            Assert.Contains("&lt;script&gt;", result.Content);
            Assert.Contains("&quot;", result.Content);
            Assert.Contains("&#39;", result.Content);
        }
    }
}