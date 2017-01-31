using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Data;
using System.Data.SqlClient;

namespace AuthenticationProvider
{
    public partial class SqlRepository
    {
        public IEnumerable<Role> GetRoles()
        {
            string query = @"SELECT r2.Id, r2.Name, Count(u.id) AS UsersCount, 
                            substring(
                            (
                                Select ', '+p.Controller + '-' + p.Action  AS [text()]
                                From Permissions p
			                    INNER JOIN PermissionsByRoles pbr ON p.Id = pbr.PermissionId
			                    INNER JOIN Roles r ON pbr.RoleId = r.Id
                                Where r.Id = r2.id
                                ORDER BY r.Id
                                For XML PATH ('')
                            ), 2, 1000) [Permissions]
                            FROM Roles r2
                            LEFT JOIN UsersRoles ur ON r2.Id = ur.RoleId 
                            LEFT JOIN WebUsers u ON ur.UserId = u.Id
                            GROUP by r2.Id, r2.Name";

            DataTable dt = DB.ExecuteDataTable(query, null);

            return dt.AsEnumerable().Select(r => new
            {
                Id = Convert.ToInt32(r["Id"]),
                Name = r["Name"].ToString(),
                UsersInRole = Convert.ToInt32(r["UsersCount"]),
                PermissionsString = r["Permissions"] == DBNull.Value? null:r["Permissions"].ToString()
            }).Select(p =>
                {
                    Role role = new Role
                    {
                        Id = p.Id,
                        Name = p.Name,
                        UsersInRole = p.UsersInRole
                    };
                    role.Permissions = new List<Permission>();
                    foreach (string permission in p.PermissionsString.Split(','))
                    {
                        role.Permissions.Add(new Permission { Controller = permission.Trim().Split('-')[0], Action = permission.Trim().Split('-')[1] });
                    }
                    return role;
                }).ToList();
        }

        public string[] GetRolesNames()
        {
            string query = @"SELECT Name FROM Roles ORDER BY Name";

            DataTable dt = DB.ExecuteDataTable(query, null);

            return dt.AsEnumerable().Select(r => r["Name"].ToString()).ToArray();
        }

        public string[] GetPermissions()
        {
            string query = @"SELECT DISTINCT Controller FROM Permissions ORDER BY Controller";

            DataTable dt = DB.ExecuteDataTable(query, null);

            return dt.AsEnumerable().Select(r => r["Controller"].ToString()).ToArray();
        }

        public bool CreateRole(Role instance)
        {
            if (CheckRoleExistings(instance) == -1)
            {
                DB.InsertNewRowAndGetItsId("Roles", new Dictionary<string, object>
                {
                    {"Name", instance.Name}
                });

                foreach (Permission permission in instance.Permissions)
                {
                    AddRolePermissions(instance.Name, permission.Controller, permission.Action);
                }

                return true;    
            }
            return false;
        }

        public bool AddRolePermissions(string roleName, string controller, string action)
        {
            int permRoleId = -1;
            DB.ExecuteRead(@"SELECT Id FROM PermissionsByRoles WHERE RoleId = (SELECT Id FROM Roles WHERE Name = @RoleName)
                            AND PermissionId = (SELECT Id FROM Permissions WHERE Controller = @Controller AND Action = @Action)",
                new Dictionary<string, object> { 
                {"@RoleName", roleName},
                    {"@Controller", controller},
                    {"@Action", action} }, delegate(SqlDataReader sdr)
                {
                    permRoleId = sdr.GetInt32(0);
                }, -1);

            if (permRoleId == -1)
            {
                string query = @"INSERT INTO PermissionsByRoles (RoleId, PermissionId) VALUES(
                            (SELECT Id FROM Roles WHERE Name = @RoleName), 
                            (SELECT Id FROM Permissions WHERE Controller = @Controller AND Action = @Action))";

                DB.ExecuteScalarQuery(query, new Dictionary<string, object>
                {
                    {"@RoleName", roleName},
                    {"@Controller", controller},
                    {"@Action", action}
                });
            }
            return true;
        }

        public bool UpdateRole(Role instance)
        {
            if (CheckRoleExistings(instance.Id))
            {
                string query = @"UPDATE Roles SET Name = @Name WHERE Id = @Id";

                DB.ExecuteScalarQuery(query, new Dictionary<string, object>
                {
                    {"@Name", instance.Name},
                    {"@Id", instance.Id}
                });

                UpdateRolePermissions(instance.Name, instance.Permissions);

                return true;
            }
            return false;
        }

        private void UpdateRolePermissions(string role, List<Permission> permissions)
        {
            List<Permission> dbPermissions = new List<Permission>();

            string query = @"SELECT p.Controller, p.Action
                            FROM Permissions p
                            LEFT JOIN PermissionsByRoles pbr ON p.id = pbr.PermissionId
                            WHERE pbr.RoleId = (SELECT Id FROM Roles WHERE Name = @RoleName)";

            DataTable dt = DB.ExecuteDataTable(query, new Dictionary<string, object> { { "@RoleName", role } });

            dbPermissions = dt.AsEnumerable().Select(r => new Permission
            {
                Controller = r["Controller"].ToString(),
                Action = r["Action"].ToString()
            }).ToList();

            foreach (Permission permission in dbPermissions)
            {
                if (permissions.Where(p => p.Controller == permission.Controller && p.Action == permission.Action).FirstOrDefault() == null)
                {
                    query = @"DELETE FROM PermissionsByRoles WHERE 
                             PermissionId = (SELECT Id FROM Permissions WHERE Controller = @Controller AND Action = @Action) AND 
                             RoleId = (SELECT Id FROM Roles WHERE Name = @RoleName)";
                    DB.ExecuteScalarQuery(query, new Dictionary<string, object>
                        {
                            {"@Controller", permission.Controller},
                            {"@Action", permission.Action},
                            {"@RoleName", role}
                        });
                }
            }

            foreach (Permission permission in permissions)
                AddRolePermissions(role, permission.Controller, permission.Action);
        }

        public bool RemoveRole(int idRole)
        {
            if (CheckRoleExistings(idRole))
            {
                string query = @"DELETE FROM UsersRoles WHERE RoleId = @Id";

                DB.ExecuteScalarQuery(query, new Dictionary<string, object>
                {
                    {"@Id", idRole}
                });

                query = @"DELETE FROM PermissionsByRoles WHERE RoleId = @Id";

                DB.ExecuteScalarQuery(query, new Dictionary<string, object>
                {
                    {"@Id", idRole}
                });

                query = @"DELETE FROM Roles WHERE Id = @Id";

                DB.ExecuteScalarQuery(query, new Dictionary<string, object>
                {
                    {"@Id", idRole}
                });
                return true;
            }

            return false;
        }

        private int CheckRoleExistings(Role role)
        {
            int roleId = -1;
            DB.ExecuteRead(@"SELECT Id FROM Roles WHERE Name = @Name",
                new Dictionary<string, object> { { "@Name", role.Name } }, delegate(SqlDataReader sdr)
                {
                    roleId = sdr.GetInt32(0);
                }, -1);

            return roleId;
        }

        private bool CheckRoleExistings(int roleId)
        {
            string query = @"SELECT DISTINCT * FROM Roles WHERE Id = @Id";

            DataTable dt = DB.ExecuteDataTable(query, new Dictionary<string, object> { { "@Id", roleId } });

            if (dt.Rows.Count > 0)
                return true;

            return false;
        }
    }
}
