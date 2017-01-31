using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Reflection;
using System.Web.Mvc;
using AuthenticationProvider.Models;
using System.Data;
using AuthenticationProvider.Filters;

namespace AuthenticationProvider
{
    public partial class SqlRepository :IRepository
    {
        public void SynchronizeWebPermissions(Assembly executingAssembly)
        {
            List<WebController> webControllers = GetAssemblyControllers(executingAssembly);
            List<WebController> dbControllers = GetDBControllers();

            foreach (WebController controller in webControllers)
            {
                string controllerName = controller.Name.Replace("Controller", "");
                foreach (string action in controller.Actions)
                {
                    DataTable dt = DB.ExecuteDataTable(@"select id FROM Permissions WHERE Controller = @Controller AND Action = @Action", new Dictionary<string, object>
                    {
                        {"@Controller", controllerName},
                        {"@Action", action}
                    });

                    if (dt.Rows.Count == 0)
                        DB.InsertNewRowAndGetItsId("Permissions", new Dictionary<string, object>
                        {
                            {"Controller", controllerName},
                            {"Action", action}
                        });
                }             
            }

            foreach (WebController controller in dbControllers)
            {
                string controllerName = string.Format("{0}Controller", controller.Name);
                foreach (string action in controller.Actions)
                {
                    if (webControllers.Where(c => c.Name == controllerName && controller.Actions.Contains(action)).FirstOrDefault() == null)
                    {
                        DB.ExecuteScalarQuery(@"DELETE FROM Permissions WHERE Controller = @Controller AND Action = @Action", new Dictionary<string, object>
                            {
                                {"@Controller", controllerName},
                                {"@Action", action}
                            });
                    }
                }
            }
        }
        /// <summary>
        /// Get List of Controllers and its Actions storing in repository
        /// </summary>
        /// <returns>List of controllers and actions</returns>
        private List<WebController> GetDBControllers()
        {
            List<WebController> dbControllers = new List<WebController>();

            DataTable dt = DB.ExecuteDataTable(@"select DISTINCT Controller FROM Permissions", null);

            string[] controllers = dt.AsEnumerable().Select(r => r["Controller"].ToString()).ToArray();

            foreach (string controller in controllers)
            {
                dt = DB.ExecuteDataTable(@"select DISTINCT Action FROM Permissions WHERE Controller = @Controller", new Dictionary<string, object>
                    {
                        {"@Controller", controller}
                    });

                WebController webController = new WebController
                {
                    Name = controller,
                    Actions = dt.AsEnumerable().Select(r=>r["Action"].ToString()).ToArray()
                };
                dbControllers.Add(webController);
            }
            return dbControllers;
        }
        /// <summary>
        /// Get Controllers and its Actions of assembly
        /// </summary>
        /// <param name="executingAssembly">Reference to executing assembly</param>
        /// <returns>List of Contollers and its Actions</returns>
        private List<WebController> GetAssemblyControllers(Assembly executingAssembly)
        {
            List<WebController> webControllers = new List<WebController>();
            var controllers = executingAssembly.GetTypes()
                .Where(type => typeof(Controller).IsAssignableFrom(type) && !type.IsDefined(typeof(NonSecurableControllerAttribute), false)).ToList();

            foreach (var controller in controllers)
            {
                WebController webController = new WebController
                {
                    Name = controller.Name,
                    Actions = controller.GetMethods(BindingFlags.Instance | BindingFlags.DeclaredOnly | BindingFlags.Public)
                    .Where(method => method.IsPublic && method.IsDefined(typeof(SecurableActionAttribute), false)).Select(method => method.Name).ToArray()
                };
                webControllers.Add(webController);
            }

            return webControllers;
        }
        public IEnumerable<ActionsByControllers> GetActionsByControllers()
        {
            List<ActionsByControllers> actionsByControllers = new List<ActionsByControllers>();
            string query = "SELECT DISTINCT Controller FROM Permissions ORDER BY Controller";
            DataTable dt = DB.ExecuteDataTable(query, null);

            string[] controllers = dt.AsEnumerable().Select(r => r["Controller"].ToString()).ToArray();

            foreach (string controller in controllers)
            {
                query = "SELECT DISTINCT Action FROM Permissions WHERE Controller = @Controller";
                dt = DB.ExecuteDataTable(query, new Dictionary<string, object> { { "@Controller", controller } });

                ActionsByControllers abc = new ActionsByControllers();
                abc.key = controller;
                abc.items = dt.AsEnumerable().Select(r => r["Action"].ToString()).ToArray();
                actionsByControllers.Add(abc);
            }

            return actionsByControllers;
        }
    }
}
