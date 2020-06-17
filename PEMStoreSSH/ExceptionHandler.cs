using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PEMStoreSSH
{
    class ExceptionHandler
    {
        public static string FlattenExceptionMessages(Exception ex, string message)
        {
            message += ex.Message + Environment.NewLine;
            if (ex.InnerException != null)
                message = FlattenExceptionMessages(ex.InnerException, message);

            return message;
        }
    }
}
