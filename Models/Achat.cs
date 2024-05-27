using BLOC3.Areas.Identity.Data;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace BLOC3.Models
{
    public class Achat
    {

        [Key]
        public int Id_Achat { get; set; }
        public DateTime DateAchat { get; set; }
        public decimal MontantTotal { get; set; }
        public Guid AchatGuid { get; set; }

        // Foreign key
        [ForeignKey("JO2024User")]
        public string? Id_Utilisateur { get; set; }
        public JO2024User? Utilisateur { get; set; }

        // Navigation property
        public ICollection<AchatEvenementOffre> AchatEvenementOffres { get; set; }

        public Achat()
        {
            AchatEvenementOffres = new List<AchatEvenementOffre>();
            AchatGuid = Guid.NewGuid();
        }
    }
}
