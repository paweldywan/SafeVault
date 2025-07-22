using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SaveVault.Models;
using SaveVault.Services;
using System.Security.Claims;

namespace SaveVault.Controllers
{
    [Authorize]
    public class DocumentsController : Controller
    {
        private readonly IDocumentService _documentService;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<DocumentsController> _logger;

        public DocumentsController(
            IDocumentService documentService,
            UserManager<ApplicationUser> userManager,
            ILogger<DocumentsController> logger)
        {
            _documentService = documentService;
            _userManager = userManager;
            _logger = logger;
        }

        [HttpGet]
        public async Task<IActionResult> Index()
        {
            try
            {
                var userId = GetCurrentUserId();
                if (string.IsNullOrEmpty(userId))
                {
                    _logger.LogWarning("User ID not found in claims");
                    return RedirectToAction("Login", "Auth");
                }

                var documents = await _documentService.GetUserDocumentsAsync(userId);
                return View(documents);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading documents for user");
                TempData["ErrorMessage"] = "An error occurred while loading your documents.";
                return View(Enumerable.Empty<Document>());
            }
        }

        [HttpGet]
        public IActionResult Create()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(Document document)
        {
            if (!ModelState.IsValid)
            {
                _logger.LogWarning("Invalid document creation attempt with validation errors");
                return View(document);
            }

            try
            {
                var userId = GetCurrentUserId();
                if (string.IsNullOrEmpty(userId))
                {
                    _logger.LogWarning("User ID not found during document creation");
                    return RedirectToAction("Login", "Auth");
                }

                document.UserId = userId;
                document.User = null; // Clear navigation property

                await _documentService.CreateDocumentAsync(document);
                
                TempData["SuccessMessage"] = "Document created successfully!";
                return RedirectToAction(nameof(Index));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating document");
                ModelState.AddModelError(string.Empty, "An error occurred while creating the document.");
                return View(document);
            }
        }

        [HttpGet]
        public async Task<IActionResult> Details(int id)
        {
            if (id <= 0)
            {
                _logger.LogWarning("Invalid document ID {DocumentId} requested", id);
                return NotFound();
            }

            try
            {
                var userId = GetCurrentUserId();
                if (string.IsNullOrEmpty(userId))
                {
                    return RedirectToAction("Login", "Auth");
                }

                var document = await _documentService.GetDocumentByIdAsync(id, userId);
                if (document == null)
                {
                    _logger.LogWarning("Document {DocumentId} not found for user {UserId}", id, userId);
                    return NotFound();
                }

                return View(document);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading document {DocumentId}", id);
                TempData["ErrorMessage"] = "An error occurred while loading the document.";
                return RedirectToAction(nameof(Index));
            }
        }

        [HttpGet]
        public async Task<IActionResult> Edit(int id)
        {
            if (id <= 0)
            {
                return NotFound();
            }

            try
            {
                var userId = GetCurrentUserId();
                if (string.IsNullOrEmpty(userId))
                {
                    return RedirectToAction("Login", "Auth");
                }

                var document = await _documentService.GetDocumentByIdAsync(id, userId);
                if (document == null)
                {
                    return NotFound();
                }

                return View(document);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading document {DocumentId} for editing", id);
                TempData["ErrorMessage"] = "An error occurred while loading the document.";
                return RedirectToAction(nameof(Index));
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, Document document)
        {
            if (id != document.Id)
            {
                _logger.LogWarning("Document ID mismatch during edit: URL ID {UrlId}, Model ID {ModelId}", id, document.Id);
                return BadRequest();
            }

            if (!ModelState.IsValid)
            {
                return View(document);
            }

            try
            {
                var userId = GetCurrentUserId();
                if (string.IsNullOrEmpty(userId))
                {
                    return RedirectToAction("Login", "Auth");
                }

                document.UserId = userId;
                document.User = null; // Clear navigation property

                var updatedDocument = await _documentService.UpdateDocumentAsync(document);
                if (updatedDocument == null)
                {
                    return NotFound();
                }

                TempData["SuccessMessage"] = "Document updated successfully!";
                return RedirectToAction(nameof(Index));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating document {DocumentId}", id);
                ModelState.AddModelError(string.Empty, "An error occurred while updating the document.");
                return View(document);
            }
        }

        [HttpGet]
        public async Task<IActionResult> Delete(int id)
        {
            if (id <= 0)
            {
                return NotFound();
            }

            try
            {
                var userId = GetCurrentUserId();
                if (string.IsNullOrEmpty(userId))
                {
                    return RedirectToAction("Login", "Auth");
                }

                var document = await _documentService.GetDocumentByIdAsync(id, userId);
                if (document == null)
                {
                    return NotFound();
                }

                return View(document);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading document {DocumentId} for deletion", id);
                TempData["ErrorMessage"] = "An error occurred while loading the document.";
                return RedirectToAction(nameof(Index));
            }
        }

        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            try
            {
                var userId = GetCurrentUserId();
                if (string.IsNullOrEmpty(userId))
                {
                    return RedirectToAction("Login", "Auth");
                }

                var result = await _documentService.DeleteDocumentAsync(id, userId);
                if (result)
                {
                    TempData["SuccessMessage"] = "Document deleted successfully!";
                }
                else
                {
                    TempData["ErrorMessage"] = "Document not found or could not be deleted.";
                }

                return RedirectToAction(nameof(Index));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting document {DocumentId}", id);
                TempData["ErrorMessage"] = "An error occurred while deleting the document.";
                return RedirectToAction(nameof(Index));
            }
        }

        private string? GetCurrentUserId()
        {
            return User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        }
    }
}