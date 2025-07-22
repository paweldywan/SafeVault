using System.ComponentModel.DataAnnotations;

namespace SaveVault.Models
{
    public class Document
    {
        public int Id { get; set; }

        [Required(ErrorMessage = "Title is required")]
        [StringLength(200, MinimumLength = 3, ErrorMessage = "Title must be between 3 and 200 characters")]
        [RegularExpression(@"^[a-zA-Z0-9\s\-_\.\,\'\!]+$", ErrorMessage = "Title contains invalid characters. Only letters, numbers, spaces, hyphens, underscores, dots, commas, apostrophes, and exclamation marks are allowed.")]
        public string Title { get; set; } = string.Empty;

        [Required(ErrorMessage = "Content is required")]
        [StringLength(5000, MinimumLength = 10, ErrorMessage = "Content must be between 10 and 5000 characters")]
        public string Content { get; set; } = string.Empty;

        [Required]
        public string UserId { get; set; } = string.Empty;
        
        public ApplicationUser? User { get; set; }

        [DataType(DataType.DateTime)]
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        [DataType(DataType.DateTime)]
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

        public bool IsDeleted { get; set; } = false;
    }
}