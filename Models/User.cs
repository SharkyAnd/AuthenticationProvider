using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Ninject;
using System.Data.SqlClient;

namespace AuthenticationProvider
{
    public partial class User
    {
        public int Id { get; set; }
        public string UserName { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public DateTime? AddedDate { get; set; }
        public DateTime? ActivateDate { get; set; }
        public string ActivationCode { get; set; }
        public DateTime? LastVisitDate { get; set; }
        public bool Confirmed { get; set; }
        public string AssociatedRoles { get; set; }

        public static string GetActivateUrl()
        {
            return Guid.NewGuid().ToString("N");
        }

        public bool InRoles(string roles, IRepository repository)
        {
            if (string.IsNullOrWhiteSpace(roles))
            {
                return false;
            }
            return repository.InRoles(roles, this.UserName);

        }
    }

    public class Role
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public List<Permission> Permissions { get; set; }
        public int UsersInRole { get; set; }
    }

    public class Rule
    {
        public int Id { get; set; }
        public string Mask { get; set; }
        public List<Permission> Permissions { get; set; }
    }

    public class Permission
    {
        public string Controller { get; set; }
        public string Action { get; set; }
    }

    public class UserRole
    {
        public int Id { get; set; }
        public string UserName { get; set; }
        public string RoleName { get; set; }
    }
}