using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace BLOC3.Models
{
    public class Offre
    {
        [Key]
        public int Id_Offre { get; set; }

        [Required(ErrorMessage = "Le type est requis.")]
        public string? Type { get; set; }

        [Required(ErrorMessage = "La description est requise.")]
        public string? Description { get; set; }

        [Range(0, 100, ErrorMessage = "Le pourcentage doit être entre 0 et 100.")]
        public int Pourcentage { get; set; }
        public int? NbPersonne { get; set; }

        // Navigation property
        public ICollection<AchatEvenementOffre> AchatEvenementOffres { get; set; } = new List<AchatEvenementOffre>();
    }
}
