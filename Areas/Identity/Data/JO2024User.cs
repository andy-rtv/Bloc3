using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using BLOC3.Models;

namespace BLOC3.Areas.Identity.Data;

// Add profile data for application users by adding properties to the JO2024User class
public class JO2024User : IdentityUser
{
    public string? FirstName { get; set; }
    public string? LastName { get; set; }

    public ICollection<Achat>? Achats { get; set; }
    public ICollection<Ticket>? Tickets { get; set; }
}

