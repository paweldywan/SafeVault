using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using SaveVault.Data;
using SaveVault.Models;
using SaveVault.Services;
using System.ComponentModel.DataAnnotations;

namespace SafeVault.Tests.Security
{
    public class InputValidationTests
    {
        private ApplicationDbContext GetInMemoryContext()
        {
            var options = new DbContextOptionsBuilder<ApplicationDbContext>()
                .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
                .Options;
            return new ApplicationDbContext(options);
        }

        [Fact]
        public void Document_Title_Should_Reject_Invalid_Characters()
        {
            // Arrange
            var document = new Document
            {
                Title = "<script>alert('xss')</script>", // XSS attempt
                Content = "Valid content",
                UserId = "test-user"
            };

            // Act
            var context = new ValidationContext(document);
            var results = new List<ValidationResult>();
            var isValid = Validator.TryValidateObject(document, context, results, true);

            // Assert
            Assert.False(isValid);
            Assert.Contains(results, r => r.ErrorMessage?.Contains("invalid characters") == true);
        }

        [Fact]
        public void Document_Title_Should_Reject_SQL_Injection_Attempts()
        {
            // Arrange
            var document = new Document
            {
                Title = "'; DROP TABLE Documents; --", // SQL injection attempt
                Content = "Valid content",
                UserId = "test-user"
            };

            // Act
            var context = new ValidationContext(document);
            var results = new List<ValidationResult>();
            var isValid = Validator.TryValidateObject(document, context, results, true);

            // Assert
            Assert.False(isValid);
            Assert.Contains(results, r => r.ErrorMessage?.Contains("invalid characters") == true);
        }

        [Fact]
        public void Document_Title_Should_Enforce_Length_Limits()
        {
            // Arrange
            var document = new Document
            {
                Title = new string('A', 201), // Exceeds 200 character limit
                Content = "Valid content",
                UserId = "test-user"
            };

            // Act
            var context = new ValidationContext(document);
            var results = new List<ValidationResult>();
            var isValid = Validator.TryValidateObject(document, context, results, true);

            // Assert
            Assert.False(isValid);
            Assert.Contains(results, r => r.ErrorMessage?.Contains("200 characters") == true);
        }

        [Fact]
        public void Document_Content_Should_Enforce_Length_Limits()
        {
            // Arrange
            var document = new Document
            {
                Title = "Valid Title",
                Content = new string('A', 5001), // Exceeds 5000 character limit
                UserId = "test-user"
            };

            // Act
            var context = new ValidationContext(document);
            var results = new List<ValidationResult>();
            var isValid = Validator.TryValidateObject(document, context, results, true);

            // Assert
            Assert.False(isValid);
            Assert.Contains(results, r => r.ErrorMessage?.Contains("5000 characters") == true);
        }

        [Fact]
        public void ApplicationUser_FullName_Should_Reject_Invalid_Characters()
        {
            // Arrange
            var user = new ApplicationUser
            {
                FullName = "John<script>alert('xss')</script>Doe", // XSS attempt in name
                Email = "john@example.com",
                UserName = "john@example.com"
            };

            // Act
            var context = new ValidationContext(user);
            var results = new List<ValidationResult>();
            var isValid = Validator.TryValidateObject(user, context, results, true);

            // Assert
            Assert.False(isValid);
            Assert.Contains(results, r => r.ErrorMessage?.Contains("letters and spaces") == true);
        }

        [Fact]
        public async Task DocumentService_Should_Sanitize_Input()
        {
            // Arrange
            using var context = GetInMemoryContext();
            var logger = new Mock<ILogger<DocumentService>>();
            var service = new DocumentService(context, logger.Object);

            var document = new Document
            {
                Title = "<script>alert('xss')</script>Test",
                Content = "Content with <script>alert('xss')</script> XSS",
                UserId = "test-user"
            };

            // Act
            var result = await service.CreateDocumentAsync(document);

            // Assert
            Assert.DoesNotContain("<script>", result.Title);
            Assert.DoesNotContain("<script>", result.Content);
            Assert.Contains("&lt;script&gt;", result.Title); // Should be HTML encoded
            Assert.Contains("&lt;script&gt;", result.Content); // Should be HTML encoded
        }

        [Theory]
        [InlineData("")]
        [InlineData("ab")] // Too short
        public void Document_Title_Should_Reject_Invalid_Lengths(string title)
        {
            // Arrange
            var document = new Document
            {
                Title = title,
                Content = "Valid content with sufficient length",
                UserId = "test-user"
            };

            // Act
            var context = new ValidationContext(document);
            var results = new List<ValidationResult>();
            var isValid = Validator.TryValidateObject(document, context, results, true);

            // Assert
            Assert.False(isValid);
        }

        [Fact]
        public void Valid_Document_Should_Pass_Validation()
        {
            // Arrange
            var document = new Document
            {
                Title = "Valid Document Title",
                Content = "This is a valid document content with sufficient length.",
                UserId = "test-user"
            };

            // Act
            var context = new ValidationContext(document);
            var results = new List<ValidationResult>();
            var isValid = Validator.TryValidateObject(document, context, results, true);

            // Assert
            Assert.True(isValid);
            Assert.Empty(results);
        }
    }
}