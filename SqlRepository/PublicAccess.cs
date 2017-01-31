using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Data.SqlClient;
using System.Data;

namespace AuthenticationProvider
{
    public partial class SqlRepository : IRepository
    {
        public bool IsUserHasAccess(string ipAddress, string controller, string action)
        {
            if (ipAddress.Split('.').Length == 1)
                return true;

            DataTable dt = DB.ExecuteDataTable(@"SELECT par.Mask FROM PermissionsByPublicAccessRules pbpa
                                                LEFT JOIN Permissions p ON pbpa.PermissionId = p.id
                                                LEFT JOIN PublicAccessRules par ON pbpa.RuleId = par.id
                                                WHERE p.Controller = @Controller AND p.Action = @Action",
            new Dictionary<string, object> { { "@Controller", controller }, { "@Action", action } });

            var rules = dt.AsEnumerable().Select(r => r["Mask"].ToString());
            foreach (string rule in rules)
            {
                string formattedRule = rule.Split('.')[0];
                string[] ruleOctets = rule.Split('.');
                for (int i = 1; i < ruleOctets.Length; i++)
                {
                    if (ruleOctets[i] != "*")
                        formattedRule += "." + ruleOctets[i];
                }

                string formattedAddress = FormatAddress(ipAddress, formattedRule.Split('.').Length);

                if (formattedRule == formattedAddress)
                    return true;
            }

            return false;
        }
        /// <summary>
        /// Format address by repository rules
        /// </summary>
        /// <param name="ipAddress">IP address of client</param>
        /// <param name="octetCount">Number of octets of rule IP mask</param>
        /// <returns>Formatted address</returns>
        private string FormatAddress(string ipAddress, int octetCount)
        {
            if (ipAddress.Split('.').Length <= 1)
                return ipAddress;

            string mask = ipAddress.Split('.')[0];
            for (int i = 1; i < octetCount; i++)
            {
                mask += '.' + ipAddress.Split('.')[i];
            }
            return mask;
        }

        public IEnumerable<Rule> GetRules()
        {
            string query = @"SELECT par2.Id, par2.Mask, 
                            substring(
                            (
                                Select ', '+p.Controller + '-' + p.Action  AS [text()]
                                From Permissions p
			                    INNER JOIN PermissionsByPublicAccessRules pbr ON p.Id = pbr.PermissionId
			                    INNER JOIN PublicAccessRules par ON pbr.RuleId = par.Id
                                Where par.Id = par2.id
                                ORDER BY par.Id
                                For XML PATH ('')
                            ), 2, 1000) [Permissions]
                            FROM PublicAccessRules par2
                            GROUP by par2.Id, par2.Mask";

            DataTable dt = DB.ExecuteDataTable(query, null);

            return dt.AsEnumerable().Select(r => new
            {
                Id = Convert.ToInt32(r["Id"]),
                Mask = r["Mask"].ToString(),
                PermissionsString = r["Permissions"] == DBNull.Value ? null : r["Permissions"].ToString()
            }).Select(p =>
            {
                Rule rule = new Rule
                {
                    Id = p.Id,
                    Mask = p.Mask
                };
                rule.Permissions = new List<Permission>();
                foreach (string permission in p.PermissionsString.Split(','))
                {
                    rule.Permissions.Add(new Permission { Controller = permission.Trim().Split('-')[0], Action = permission.Trim().Split('-')[1] });
                }
                return rule;
            }).ToList();
        }

        public bool CreateRule(Rule instance)
        {
            if (CheckRuleExistings(instance) == -1)
            {
                DB.InsertNewRowAndGetItsId("PublicAccessRules", new Dictionary<string, object>
                {
                    {"Mask", instance.Mask}
                });

                foreach (Permission permission in instance.Permissions)
                {
                    AddRulePermissions(instance.Mask, permission.Controller, permission.Action);
                }

                return true;
            }
            return false;
        }

        public bool AddRulePermissions(string ruleMask, string controller, string action)
        {
            int permRuleId = -1;
            DB.ExecuteRead(@"SELECT Id FROM PermissionsByPublicAccessRules WHERE RuleId = (SELECT Id FROM PublicAccessRules WHERE Mask = @Mask)
                            AND PermissionId = (SELECT Id FROM Permissions WHERE Controller = @Controller AND Action = @Action)",
                new Dictionary<string, object> { 
                {"@Mask", ruleMask},
                    {"@Controller", controller},
                    {"@Action", action} }, delegate(SqlDataReader sdr)
                    {
                        permRuleId = sdr.GetInt32(0);
                    }, -1);

            if (permRuleId == -1)
            {
                string query = @"INSERT INTO PermissionsByPublicAccessRules (RuleId, PermissionId) VALUES(
                            (SELECT Id FROM PublicAccessRules WHERE Mask = @Mask), 
                            (SELECT Id FROM Permissions WHERE Controller = @Controller AND Action = @Action))";

                DB.ExecuteScalarQuery(query, new Dictionary<string, object>
                {
                    {"@Mask", ruleMask},
                    {"@Controller", controller},
                    {"@Action", action}
                });
            }
            return true;
        }

        public bool UpdateRule(Rule instance)
        {
            if (CheckRuleExistings(instance.Id))
            {
                string query = @"UPDATE PublicAccessRules SET Mask = @Mask WHERE Id = @Id";

                DB.ExecuteScalarQuery(query, new Dictionary<string, object>
                {
                    {"@Mask", instance.Mask},
                    {"@Id", instance.Id}
                });

                UpdateRulePermissions(instance.Mask, instance.Permissions);

                return true;
            }
            return false;
        }
        /// <summary>
        /// Update existing rule permissions
        /// </summary>
        /// <param name="mask">Mask of rule</param>
        /// <param name="permissions">Permissions</param>
        private void UpdateRulePermissions(string mask, List<Permission> permissions)
        {
            List<Permission> dbPermissions = new List<Permission>();

            string query = @"SELECT p.Controller, p.Action
                            FROM Permissions p
                            LEFT JOIN PermissionsByPublicAccessRules pbr ON p.id = pbr.PermissionId
                            WHERE pbr.RuleId = (SELECT Id FROM PublicAccessRules WHERE Mask = @Mask)";

            DataTable dt = DB.ExecuteDataTable(query, new Dictionary<string, object> { { "@Mask", mask } });

            dbPermissions = dt.AsEnumerable().Select(r => new Permission
            {
                Controller = r["Controller"].ToString(),
                Action = r["Action"].ToString()
            }).ToList();

            foreach (Permission permission in dbPermissions)
            {
                if (permissions.Where(p => p.Controller == permission.Controller && p.Action == permission.Action).FirstOrDefault() == null)
                {
                    query = @"DELETE FROM PermissionsByPublicAccessRules WHERE 
                             PermissionId = (SELECT Id FROM Permissions WHERE Controller = @Controller AND Action = @Action) AND 
                             RuleId = (SELECT Id FROM PublicAccessRules WHERE Mask = @Mask)";
                    DB.ExecuteScalarQuery(query, new Dictionary<string, object>
                        {
                            {"@Controller", permission.Controller},
                            {"@Action", permission.Action},
                            {"@Mask", mask}
                        });
                }
            }

            foreach (Permission permission in permissions)
                AddRulePermissions(mask, permission.Controller, permission.Action);
        }

        public bool RemoveRule(int idRule)
        {
            if (CheckRuleExistings(idRule))
            {
                string query = @"DELETE FROM PermissionsByPublicAccessRules WHERE RuleId = @Id";

                DB.ExecuteScalarQuery(query, new Dictionary<string, object>
                {
                    {"@Id", idRule}
                });

                query = @"DELETE FROM PublicAccessRules WHERE Id = @Id";

                DB.ExecuteScalarQuery(query, new Dictionary<string, object>
                {
                    {"@Id", idRule}
                });
                return true;
            }

            return false;
        }
        /// <summary>
        /// Check rule existing
        /// </summary>
        /// <param name="rule">Instance of rule</param>
        /// <returns>Rule id</returns>
        private int CheckRuleExistings(Rule rule)
        {
            int ruleId = -1;
            DB.ExecuteRead(@"SELECT Id FROM PublicAccessRules WHERE Mask = @Mask",
                new Dictionary<string, object> { { "@Mask", rule.Mask } }, delegate(SqlDataReader sdr)
                {
                    ruleId = sdr.GetInt32(0);
                }, -1);

            return ruleId;
        }
        /// <summary>
        /// Check rule existing
        /// </summary>
        /// <param name="ruleId">Rule id</param>
        /// <returns>Result</returns>
        private bool CheckRuleExistings(int ruleId)
        {
            string query = @"SELECT DISTINCT * FROM PublicAccessRules WHERE Id = @Id";

            DataTable dt = DB.ExecuteDataTable(query, new Dictionary<string, object> { { "@Id", ruleId } });

            if (dt.Rows.Count > 0)
                return true;

            return false;
        }
    }
}
