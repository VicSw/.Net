using System.Runtime.InteropServices;
using System;
using System.ComponentModel;
using System.IO;

namespace WebApplication8
{
         
enum LogonType : uint
    {
        
        Interactive = 2,
       
        Network = 3,
        
        Batch = 4,
       
        Service = 5,
        
        Unlock = 7,
        
        NetworkClearText = 8,
        
        NewCredentials = 9
    }
enum LogonProvider : uint
    {
        
        Default = 0,
        
        WinNT35 = 1,
        
        WinNT40 = 2,
       
        WinNT50 = 3,
    }
class IdentityScope : IDisposable
    {
        [DllImport("Advapi32.dll")]
        static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword,
            LogonType dwLogonType, LogonProvider dwLogonProvider, out IntPtr phToken);
        [DllImport("Advapi32.DLL")]
        static extern bool ImpersonateLoggedOnUser(IntPtr hToken);
        [DllImport("Advapi32.DLL")]
        static extern bool RevertToSelf();
        [DllImport("Kernel32.dll")]
        static extern int GetLastError();

        bool disposed;

        public IdentityScope(string domain, string userName, string password): this(domain, userName, password, LogonType.Interactive, LogonProvider.Default)
        {
        }

        public IdentityScope(string domain, string userName, string password, LogonType logonType, LogonProvider logonProvider)
        {
            if (string.IsNullOrEmpty(userName))
            {
                throw new ArgumentNullException("userName");
            }
            if (string.IsNullOrEmpty(domain))
            {
                domain = ".";
            }

            IntPtr token;
            int errorCode = 0;
            if (LogonUser(userName, domain, password, logonType, logonProvider, out token))
            {
                if (!ImpersonateLoggedOnUser(token))
                {
                    errorCode = GetLastError(); 
                }
            }
            else
            {
                errorCode = GetLastError();
            }
            if (errorCode != 0)
            {
                throw new Win32Exception(errorCode);
            }
        }

        ~IdentityScope()
        {
            Dispose(false);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!disposed)
            {
                if (disposing)
                {
                    // Nothing to do.
                }
                RevertToSelf();
                disposed = true;
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
    
}