using BLOC3.Areas.Identity.Data;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;

namespace BLOC3.Models
{
    public class Ticket
    {
        [Key]
        public int Id_Ticket { get; set; }
        public DateTime CreationDate { get; set; }
        public string? QRCodePath { get; set; }

        [Required]
        public Guid TicketGuid { get; set; } = Guid.NewGuid();

        // Foreign key
        [ForeignKey("JO2024User")]
        public string? Id_Utilisateur { get; set; }
        public JO2024User? Utilisateur { get; set; }

        // Foreign key
        public int Id_AchatEvenementOffre { get; set; }
        public AchatEvenementOffre? AchatEvenementOffre { get; set; }
    }
}
