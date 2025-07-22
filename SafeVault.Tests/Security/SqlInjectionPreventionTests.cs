using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Services;

namespace SafeVault.Tests.Security
{
    public class SqlInjectionPreventionTests
    {
        private ApplicationDbContext GetInMemoryContext()
        {
            var options = new DbContextOptionsBuilder<ApplicationDbContext>()
                .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
                .Options;
            return new ApplicationDbContext(options);
        }

        [Fact]
        public async Task GetUserDocuments_Should_Use_Parameterized_Queries()
        {
            // Arrange
            using var context = GetInMemoryContext();
            var logger = new Mock<ILogger<DocumentService>>();
            var service = new DocumentService(context, logger.Object);

            var maliciousUserId = "'; DROP TABLE Documents; --";

            // Create a legitimate document first
            var legitimateDoc = new Document
            {
                Title = "Legitimate Document",
                Content = "Legitimate content",
                UserId = "legitimate-user"
            };
            context.Documents.Add(legitimateDoc);
            await context.SaveChangesAsync();

            // Act - This should not cause any SQL injection
            var result = await service.GetUserDocumentsAsync(maliciousUserId);

            // Assert
            Assert.Empty(result); // Should return empty for non-existent user
            
            // Verify the legitimate document still exists (wasn't dropped)
            var existingDocs = await context.Documents.ToListAsync();
            Assert.Single(existingDocs);
            Assert.Equal("Legitimate Document", existingDocs[0].Title);
        }

        [Fact]
        public async Task GetDocumentById_Should_Prevent_SQL_Injection()
        {
            // Arrange
            using var context = GetInMemoryContext();
            var logger = new Mock<ILogger<DocumentService>>();
            var service = new DocumentService(context, logger.Object);

            var maliciousUserId = "1' OR '1'='1"; // SQL injection attempt

            var document = new Document
            {
                Title = "Test Document",
                Content = "Test content",
                UserId = "legitimate-user"
            };
            context.Documents.Add(document);
            await context.SaveChangesAsync();

            // Act - Malicious user trying to access document
            var result = await service.GetDocumentByIdAsync(document.Id, maliciousUserId);

            // Assert
            Assert.Null(result); // Should not return document for unauthorized user
        }

        [Fact]
        public async Task CreateDocument_Should_Handle_Malicious_Input_Safely()
        {
            // Arrange
            using var context = GetInMemoryContext();
            var logger = new Mock<ILogger<DocumentService>>();
            var service = new DocumentService(context, logger.Object);

            var originalTitle = "'; DROP TABLE Users; --";
            var originalContent = "1' UNION SELECT * FROM Users WHERE '1'='1";
            
            var maliciousDocument = new Document
            {
                Title = originalTitle,
                Content = originalContent,
                UserId = "test-user"
            };

            // Act
            var result = await service.CreateDocumentAsync(maliciousDocument);

            // Assert
            Assert.NotNull(result);
            Assert.True(result.Id > 0);
            
            // Verify the malicious content is sanitized via HTML encoding
            // The original strings are preserved but made safe
            Assert.NotEqual(originalTitle, result.Title); // Should be different due to encoding
            Assert.NotEqual(originalContent, result.Content); // Should be different due to encoding
            
            // The content should be HTML encoded
            Assert.Contains("&#39;", result.Title); // Single quote should be encoded
        }

        [Theory]
        [InlineData("' OR 1=1 --")]
        [InlineData("'; DROP TABLE Documents; --")]
        [InlineData("1' UNION SELECT * FROM Users --")]
        [InlineData("admin'/*")]
        [InlineData("' OR 'x'='x")]
        public async Task DocumentService_Should_Reject_SQL_Injection_In_UserId(string maliciousUserId)
        {
            // Arrange
            using var context = GetInMemoryContext();
            var logger = new Mock<ILogger<DocumentService>>();
            var service = new DocumentService(context, logger.Object);

            // Add a legitimate document
            var legitimateDoc = new Document
            {
                Title = "Test Document",
                Content = "Test content",
                UserId = "legitimate-user"
            };
            context.Documents.Add(legitimateDoc);
            await context.SaveChangesAsync();

            // Act - Try to get documents with malicious user ID
            var result = await service.GetUserDocumentsAsync(maliciousUserId);

            // Assert
            Assert.Empty(result); // Should not return any documents
            
            // Verify legitimate document still exists
            var allDocs = await context.Documents.ToListAsync();
            Assert.Single(allDocs);
        }

        [Fact]
        public async Task UpdateDocument_Should_Prevent_SQL_Injection()
        {
            // Arrange
            using var context = GetInMemoryContext();
            var logger = new Mock<ILogger<DocumentService>>();
            var service = new DocumentService(context, logger.Object);

            var originalDoc = new Document
            {
                Title = "Original Title",
                Content = "Original content",
                UserId = "legitimate-user"
            };
            context.Documents.Add(originalDoc);
            await context.SaveChangesAsync();

            var maliciousUpdate = new Document
            {
                Id = originalDoc.Id,
                Title = "'; UPDATE Users SET IsAdmin=1 WHERE '1'='1'; --",
                Content = "Malicious content",
                UserId = "legitimate-user"
            };

            // Act
            var result = await service.UpdateDocumentAsync(maliciousUpdate);

            // Assert
            Assert.NotNull(result);
            
            // The content should be HTML encoded, making it safe
            Assert.NotEqual(maliciousUpdate.Title, result.Title); // Should be different due to encoding
            Assert.Contains("&#39;", result.Title); // Should be HTML encoded
        }

        [Fact]
        public async Task DeleteDocument_Should_Prevent_SQL_Injection()
        {
            // Arrange
            using var context = GetInMemoryContext();
            var logger = new Mock<ILogger<DocumentService>>();
            var service = new DocumentService(context, logger.Object);

            var document = new Document
            {
                Title = "Test Document",
                Content = "Test content",
                UserId = "legitimate-user"
            };
            context.Documents.Add(document);
            await context.SaveChangesAsync();

            var maliciousUserId = "1' OR '1'='1"; // Attempt to delete all documents

            // Act
            var result = await service.DeleteDocumentAsync(document.Id, maliciousUserId);

            // Assert
            Assert.False(result); // Should fail to delete (unauthorized user)
            
            // Verify document still exists
            var existingDoc = await context.Documents.FindAsync(document.Id);
            Assert.NotNull(existingDoc);
            Assert.False(existingDoc.IsDeleted);
        }

        [Fact]
        public async Task DocumentExists_Should_Prevent_SQL_Injection()
        {
            // Arrange
            using var context = GetInMemoryContext();
            var logger = new Mock<ILogger<DocumentService>>();
            var service = new DocumentService(context, logger.Object);

            var document = new Document
            {
                Title = "Test Document",
                Content = "Test content",
                UserId = "legitimate-user"
            };
            context.Documents.Add(document);
            await context.SaveChangesAsync();

            var maliciousUserId = "1' OR '1'='1";

            // Act
            var result = await service.DocumentExistsAsync(document.Id, maliciousUserId);

            // Assert
            Assert.False(result); // Should return false for unauthorized user
        }

        [Fact]
        public async Task All_Operations_Should_Use_Parameterized_Queries()
        {
            // Arrange
            using var context = GetInMemoryContext();
            var logger = new Mock<ILogger<DocumentService>>();
            var service = new DocumentService(context, logger.Object);

            // Create test data
            var testDoc = new Document
            {
                Title = "Test Document",
                Content = "Test content",
                UserId = "legitimate-user"
            };
            context.Documents.Add(testDoc);
            await context.SaveChangesAsync();

            var maliciousUserId = "'; DROP DATABASE; --";

            // Act - Try all operations with malicious user ID
            var getUserDocs = await service.GetUserDocumentsAsync(maliciousUserId);
            var getDocById = await service.GetDocumentByIdAsync(testDoc.Id, maliciousUserId);
            var docExists = await service.DocumentExistsAsync(testDoc.Id, maliciousUserId);
            var deleteResult = await service.DeleteDocumentAsync(testDoc.Id, maliciousUserId);

            // Assert - All operations should fail safely without SQL injection
            Assert.Empty(getUserDocs);
            Assert.Null(getDocById);
            Assert.False(docExists);
            Assert.False(deleteResult);

            // Verify original data is still intact
            var remainingDocs = await context.Documents.ToListAsync();
            Assert.Single(remainingDocs);
            Assert.Equal("Test Document", remainingDocs[0].Title);
        }
    }
}