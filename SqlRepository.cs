using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Ninject;
using System.Reflection;

namespace AuthenticationProvider
{
    public partial class SqlRepository : IRepository
    {
        [Inject]
        public Utils.DatabaseUtils DB { get; set; }
    }
}
