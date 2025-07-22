using Microsoft.EntityFrameworkCore;
using SafeVault.Data;
using SafeVault.Models;
using Microsoft.AspNetCore.Html;
using System.Web;

namespace SafeVault.Services
{
    public interface IDocumentService
    {
        Task<IEnumerable<Document>> GetUserDocumentsAsync(string userId);
        Task<Document?> GetDocumentByIdAsync(int id, string userId);
        Task<Document> CreateDocumentAsync(Document document);
        Task<Document?> UpdateDocumentAsync(Document document);
        Task<bool> DeleteDocumentAsync(int id, string userId);
        Task<bool> DocumentExistsAsync(int id, string userId);
    }

    public class DocumentService : IDocumentService
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<DocumentService> _logger;

        public DocumentService(ApplicationDbContext context, ILogger<DocumentService> logger)
        {
            _context = context;
            _logger = logger;
        }

        public async Task<IEnumerable<Document>> GetUserDocumentsAsync(string userId)
        {
            if (string.IsNullOrWhiteSpace(userId))
            {
                _logger.LogWarning("GetUserDocumentsAsync called with null or empty userId");
                return Enumerable.Empty<Document>();
            }

            try
            {
                // Using parameterized query to prevent SQL injection
                return await _context.Documents
                    .Where(d => d.UserId == userId && !d.IsDeleted)
                    .OrderByDescending(d => d.UpdatedAt)
                    .ToListAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving documents for user {UserId}", userId);
                return Enumerable.Empty<Document>();
            }
        }

        public async Task<Document?> GetDocumentByIdAsync(int id, string userId)
        {
            if (string.IsNullOrWhiteSpace(userId) || id <= 0)
            {
                _logger.LogWarning("GetDocumentByIdAsync called with invalid parameters: id={Id}, userId={UserId}", id, userId);
                return null;
            }

            try
            {
                // Using parameterized query with authorization check
                return await _context.Documents
                    .FirstOrDefaultAsync(d => d.Id == id && d.UserId == userId && !d.IsDeleted);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving document {DocumentId} for user {UserId}", id, userId);
                return null;
            }
        }

        public async Task<Document> CreateDocumentAsync(Document document)
        {
            if (document == null)
                throw new ArgumentNullException(nameof(document));

            // Sanitize input to prevent XSS
            document.Title = SanitizeInput(document.Title);
            document.Content = SanitizeInput(document.Content);

            try
            {
                document.CreatedAt = DateTime.UtcNow;
                document.UpdatedAt = DateTime.UtcNow;

                _context.Documents.Add(document);
                await _context.SaveChangesAsync();

                _logger.LogInformation("Document {DocumentId} created for user {UserId}", document.Id, document.UserId);
                return document;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating document for user {UserId}", document.UserId);
                throw;
            }
        }

        public async Task<Document?> UpdateDocumentAsync(Document document)
        {
            if (document == null)
                throw new ArgumentNullException(nameof(document));

            try
            {
                var existingDocument = await GetDocumentByIdAsync(document.Id, document.UserId);
                if (existingDocument == null)
                {
                    _logger.LogWarning("Attempted to update non-existent document {DocumentId} for user {UserId}", document.Id, document.UserId);
                    return null;
                }

                // Sanitize input to prevent XSS
                existingDocument.Title = SanitizeInput(document.Title);
                existingDocument.Content = SanitizeInput(document.Content);
                existingDocument.UpdatedAt = DateTime.UtcNow;

                _context.Documents.Update(existingDocument);
                await _context.SaveChangesAsync();

                _logger.LogInformation("Document {DocumentId} updated for user {UserId}", document.Id, document.UserId);
                return existingDocument;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating document {DocumentId} for user {UserId}", document.Id, document.UserId);
                throw;
            }
        }

        public async Task<bool> DeleteDocumentAsync(int id, string userId)
        {
            if (string.IsNullOrWhiteSpace(userId) || id <= 0)
            {
                _logger.LogWarning("DeleteDocumentAsync called with invalid parameters: id={Id}, userId={UserId}", id, userId);
                return false;
            }

            try
            {
                var document = await GetDocumentByIdAsync(id, userId);
                if (document == null)
                {
                    _logger.LogWarning("Attempted to delete non-existent document {DocumentId} for user {UserId}", id, userId);
                    return false;
                }

                // Soft delete for security audit trail
                document.IsDeleted = true;
                document.UpdatedAt = DateTime.UtcNow;

                _context.Documents.Update(document);
                await _context.SaveChangesAsync();

                _logger.LogInformation("Document {DocumentId} deleted for user {UserId}", id, userId);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting document {DocumentId} for user {UserId}", id, userId);
                return false;
            }
        }

        public async Task<bool> DocumentExistsAsync(int id, string userId)
        {
            if (string.IsNullOrWhiteSpace(userId) || id <= 0)
                return false;

            try
            {
                return await _context.Documents
                    .AnyAsync(d => d.Id == id && d.UserId == userId && !d.IsDeleted);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking document existence {DocumentId} for user {UserId}", id, userId);
                return false;
            }
        }

        private static string SanitizeInput(string input)
        {
            if (string.IsNullOrWhiteSpace(input))
                return string.Empty;

            // HTML encode to prevent XSS attacks
            return HttpUtility.HtmlEncode(input.Trim());
        }
    }
}