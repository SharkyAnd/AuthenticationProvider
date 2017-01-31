using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace AuthenticationProvider.Models
{
    public class ConfirmationDataModel
    {
        public string UserName { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public string ActivationCode { get; set; }
        public string AssociatedRoles { get; set; }
    }
}
