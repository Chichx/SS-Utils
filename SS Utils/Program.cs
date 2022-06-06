using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Threading;
using Microsoft.Win32;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace SSUtils
{
    class Program
    {
        static void Main(string[] args)
        {


            Console.Title = "github.com/Chichx | SS Utils";

            {
                Console.WriteLine(@"         _ _   _           _       ______ _     _      _          
   __ _(_) |_| |__  _   _| |__   / / ___| |__ (_) ___| |__ __  __
  / _` | | __| '_ \| | | | '_ \ / / |   | '_ \| |/ __| '_ \\ \/ /
 | (_| | | |_| | | | |_| | |_) / /| |___| | | | | (__| | | |>  < 
  \__, |_|\__|_| |_|\__,_|_.__/_/  \____|_| |_|_|\___|_| |_/_/\_\
  |___/ " + Environment.NewLine, Console.ForegroundColor = ConsoleColor.Magenta);
            }
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("[1] Time Modification");
            Console.WriteLine("[2] Partition Disks");
            Console.WriteLine("[3] Executed Programs");
            Console.WriteLine("[4] Pcasvc");
            Console.WriteLine("[5] Credits");
            Console.Write("Your choice: ");
            int option = Convert.ToInt32(Console.ReadLine());
            switch (option)
            {
                default:
                    Console.WriteLine("Not a valid option.");
                    Thread.Sleep(2000);
                    Console.Clear();
                    Main(args);
                    break;
                case 1:
                    Console.Title = $"github.com/Chichx | Time Modification";
                    Console.Clear();
                    Modification(args);
                    break;
                case 2:
                    Console.Title = $"github.com/Chichx | Partition Disk";
                    Console.Clear();
                    Partition(args);
                    break;
                case 3:
                    Console.Title = $"github.com/Chichx | Executed Programs";
                    Console.Clear();
                    ExecutedPrograms(args);
                    break;
                case 4:
                    Console.Title = $"github.com/Chichx | PcaClient Viewer";
                    Console.Clear();
                    PcaSvc(args);
                    break;
                case 5:
                    Console.Title = $"github.com/Chichx | Credits";
                    Console.Clear();
                    Credits(args);
                    break;
            }
        }

        //
        // Time Modification Codigo
        //
        class CheckInfo
        {
            public CheckInfo(bool result, DateTime previousTime, DateTime newTime, DateTime? generatedAt, long? recordIdentifier)
            {
                this.Result = result;
                this.Previous = previousTime;
                this.New = newTime;
                this.Time = generatedAt;
                this.Id = recordIdentifier;
            }

            public CheckInfo(bool result)
            {
                this.Result = result;
            }

            public bool Result { get; }
            public DateTime Previous { get; }
            public DateTime New { get; }
            public DateTime? Time { get; }
            public long? Id { get; }

        };

        private static void Credits(string[] args)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(@"    ____ _     _      _           
  / ___| |__ (_) ___| |__   ___  
 | |   | '_ \| |/ __| '_ \ / _ \ 
 | |___| | | | | (__| | | | (_) |
  \____|_| |_|_|\___|_| |_|\___/ ");
            Console.WriteLine("\n\nCreated by Chicho");
            Console.WriteLine("Discord: Chicho#54393");
            Console.WriteLine("Guthub: https://github.com/Chichx");
            Console.WriteLine("\n\nPress ENTER to go to the menu...");
            Console.ReadLine();
            Console.Clear();
            Main(args);

        }

        private static void Modification(string[] args) {

            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("Analyzing logs...\n\n");
            CheckInfo info = checkTimeModification();
            Thread.Sleep(2000);
            if (info.Result)
            {
                Console.WriteLine("[!] Find changed dates!");
                Console.WriteLine("Previous time: {0} | New Time: {1}\nGenerated at: {2} | Record ID: {3}\n\n",
                    info.Previous, info.New, info.Time, info.Id);
            }
            else Console.WriteLine("[?] It seems that this person did not change anything!\n\n");

            Console.Write("\n\nPress ENTER to go to the menu...");
            Console.ReadLine();
            Console.Clear();
            Main(args);
        }

        static CheckInfo checkTimeModification() 
        {
            EventRecord entry;
            string logPath = @"C:\Windows\System32\winevt\Logs\Security.evtx";
            EventLogReader logReader = new EventLogReader(logPath, PathType.FilePath);
            DateTime pcStartTime = startTime();

            while ((entry = logReader.ReadEvent()) != null)
            {
                if (entry.Id != 4616) continue; // Esta id ve la fecha de modificacion del dispositivo.
                if (entry.TimeCreated <= pcStartTime) continue;

                IList<EventProperty> properties = entry.Properties;
                DateTime previousTime = DateTime.Parse(properties[4].Value.ToString());
                DateTime newTime = DateTime.Parse(properties[5].Value.ToString());

                if (Math.Abs((previousTime - newTime).TotalMinutes) > 5)
                    return new CheckInfo(true, previousTime, newTime, entry.TimeCreated, entry.RecordId);
            }
            return new CheckInfo(false);
        }

    class PartitionInfo
    {
        public PartitionInfo(char letter, bool isMounted)
        {
            this.Letter = letter;
            this.IsMounted = isMounted;
        }

        public char Letter { get; }
        public bool IsMounted { get; }
    }

    class DiskLog
    {
        public DiskLog(string name, DateTime? generatedAt, long? recordIdentifier)
        {
            this.Name = name;
            this.Time = generatedAt;
            this.Id = recordIdentifier;
        }

        public string Name { get; }
        public DateTime? Time { get; }
        public long? Id { get; }
    }

        private static void Partition(string[] args)
        {
            List<PartitionInfo> partitionsInfo = new List<PartitionInfo>();
            getPartitions().ForEach(p => partitionsInfo.Add(new PartitionInfo(p, isMounted(p))));
            Console.ForegroundColor = ConsoleColor.White;

            Console.WriteLine("Partitions\n-------------------------------\n");
            partitionsInfo.ForEach(i =>
            {
                Console.WriteLine("Letter: {0}\n => Mounted: {1}", i.Letter, i.IsMounted);
            });

            Console.WriteLine();

            Console.WriteLine("USB storages\n-------------------------------\n");
            getRemovableStorages().ForEach(s => Console.WriteLine(s));

            Console.WriteLine();

            Console.WriteLine("Disks logs\n-------------------------------\n");
            getDisksLogs().ForEach(l =>
            {
                Console.WriteLine("Disk name: {0}\n => Generated at: {1}\n => Record ID: {2}",
                    l.Name, l.Time, l.Id);
            });

            Console.Write("\n\nPress ENTER to go to the menu...");
            Console.ReadLine();
            Console.Clear();
            Main(args);
        }

        static List<char> getPartitions()
        {
            List<char> partitions = new List<char>();
            Regex regex = new Regex(@"^\\DosDevices\\(\w):$");
            RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\MountedDevices"); // Muestra volumenes activos de tu dispositivo
            string[] values = key.GetValueNames();

            foreach (string v in values)
            {
                Match match = regex.Match(v);

                if (!match.Success) continue;

                string partition = match.Groups[1].Value;
                partitions.Add(Convert.ToChar(partition));
            }

            return partitions;
        }

        static List<string> getRemovableStorages()
        {
            List<string> storages = new List<string>();
            RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\USBSTOR"); // Ver si el usuario tiene o removio algun USB
            string[] storagesKeys = key.GetSubKeyNames();

            storagesKeys.ToList().ForEach(k =>
            {
                RegistryKey storageKey = key.OpenSubKey(k);
                RegistryKey storageInfoKey = storageKey.OpenSubKey(storageKey.GetSubKeyNames()[0]);
                string storage = storageInfoKey.GetValue("FriendlyName").ToString();
                storages.Add(storage);
            });

            return storages;
        }

        static List<DiskLog> getDisksLogs()
        {
            EventRecord entry;
            List<DiskLog> disksLogs = new List<DiskLog>();
            string logPath = @"C:\Windows\System32\winevt\Logs\Microsoft-Windows-StorageSpaces-Driver%4Operational.evtx"; 
            EventLogReader logReader = new EventLogReader(logPath, PathType.FilePath);
            DateTime pcStartTime = startTime();

            while ((entry = logReader.ReadEvent()) != null)
            {
                if (entry.Id != 207) continue; // Esta id muestra los espacios de almacenamiento
                if (entry.TimeCreated <= pcStartTime) continue;

                IList<EventProperty> properties = entry.Properties;
                string driveManufacturer = properties[3].Value.ToString();
                string driveModelNumber = properties[4].Value.ToString();

                if (driveManufacturer == "NULL") driveManufacturer = "";
                else driveManufacturer += " ";

                disksLogs.Add(new DiskLog($"{driveManufacturer}{driveModelNumber}",
                    entry.TimeCreated, entry.RecordId));
            }

            return disksLogs;
        }

        static bool isMounted(char partition)
        {
            return Directory.Exists($"{partition}:");
        }

        //
        // ExecutedPrograms Codigo
        //
        class ProgramInfo
        {
            public ProgramInfo(string fileName, DateTime? lastModified,
                DateTime? createdOn, double size)
            {
                this.FileName = fileName;
                this.LastModified = lastModified;
                this.CreatedOn = createdOn;
                this.Size = size;
            }

            public string FileName { get; }
            public DateTime? LastModified { get; }
            public DateTime? CreatedOn { get; }
            public double Size { get; }
        }

        enum Order
        {
            FileName,
            LastModified,
            CreatedOn,
            Size,
            Random
        }

        static HashSet<string> programs = new HashSet<string>();

        static void ExecutedPrograms(string[] args)
        {
            Console.ForegroundColor = ConsoleColor.White;
            List<ProgramInfo> programsInfo = new List<ProgramInfo>();
            Order orderFlag = Order.Random;
            bool save = false; string savePath = string.Empty;

            FileStream fstream = new FileStream(@"C:\tmpout.txt",
                FileMode.OpenOrCreate, FileAccess.Write);
            StreamWriter writer = new StreamWriter(fstream);
            TextWriter oldOut = Console.Out;

            if (args.Length > 0)
            {
                if (args.Contains("-orderby"))
                {
                    int index = Array.IndexOf(args, "-orderby");
                    string argValue = args[index + 1].ToLower();
                    if (argValue != "filename" && argValue != "lastmodified"
                        && argValue != "createdon" && argValue != "size")
                    {
                        Console.WriteLine("[!] Missing argument value: " +
                        "(filename|lastmodified|createdon|size");
                        Environment.Exit(-1);
                    }
                    if (argValue == "filename")
                        orderFlag = Order.FileName;
                    else if (argValue == "lastmodified")
                        orderFlag = Order.LastModified;
                    else if (argValue == "createdon")
                        orderFlag = Order.CreatedOn;
                    else if (argValue == "size")
                        orderFlag = Order.Size;
                    else
                    {
                        Console.WriteLine("[!] Invalid argument value");
                        Environment.Exit(-1);
                    }
                }

                if (args.Contains("-save"))
                {
                    int index = Array.IndexOf(args, "-save");
                    save = true; savePath = args[index + 1];
                }
            }

            getMuiCache(); getStore();

            foreach (string p in programs)
                programsInfo.Add(getProgramInfo(p));

            if (orderFlag == Order.FileName)
                programsInfo = programsInfo.OrderBy(p => p.FileName).ToList();
            if (orderFlag == Order.LastModified)
                programsInfo = programsInfo.OrderBy(p => p.LastModified).ToList();
            if (orderFlag == Order.CreatedOn)
                programsInfo = programsInfo.OrderBy(p => p.CreatedOn).ToList();
            if (orderFlag == Order.Size)
                programsInfo = programsInfo.OrderBy(p => p.Size).ToList();

            if (save)
            {
                fstream = new FileStream(savePath, FileMode.OpenOrCreate, FileAccess.Write);
                writer = new StreamWriter(fstream);
                Console.SetOut(writer);
            }

            Console.WriteLine("github/Chichx | ExecutedPrograms\n\n");

            foreach (ProgramInfo info in programsInfo)
            {
                string lastModified, createdOn, size;

                if (info.LastModified == null) lastModified = string.Empty;
                else lastModified = info.LastModified.ToString();

                if (info.CreatedOn == null) createdOn = string.Empty;
                else createdOn = info.CreatedOn.ToString();

                if (info.Size == 0) size = string.Empty;
                else size = info.Size.ToString() + "MB";

                Console.WriteLine("File: {0}\n => Last modified: {1}\n" +
                    " => Created on: {2}\n => Size: {3}",
                    info.FileName, lastModified, createdOn, size);
                Console.WriteLine("\n\n");
            }

            Console.SetOut(oldOut); writer.Close(); fstream.Close();

            Console.Write("\n\nPress ENTER to go to the menu...");
            if (!save) Console.ReadLine();
            Console.Clear();    
            Main(args);
        }

        static void getMuiCache()
        {
            Regex rgx = new Regex(@"^(\w:\\.+.exe)(.FriendlyAppName|.ApplicationCompany)$");
            RegistryKey key = Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"); // MuiCache muestra aplicaciones.
            string[] values = key.GetValueNames();

            foreach (string v in values)
            {
                Match match = rgx.Match(v);
                if (!match.Success) continue;

                string program = match.Groups[1].Value;
                programs.Add(program);
            }
        }

        static void getStore()
        {
            Regex rgx = new Regex(@"^\w:\\.+.exe$");
            RegistryKey key = Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store"); // Podremos ver los .exe ejecutados por el usuario.
            string[] values = key.GetValueNames();

            foreach (string v in values)
            {
                if (!Char.IsUpper(v[0])) continue;

                Match match = rgx.Match(v);
                if (!match.Success) continue;

                string program = match.Groups[0].Value;
                programs.Add(program);
            }
        }

        static ProgramInfo getProgramInfo(string fileName)
        {
            DateTime? lastModified = null, createdOn = null;
            double megaBytes = 0;
            FileInfo program = new FileInfo(fileName);

            if (program.Exists)
            {
                lastModified = program.LastWriteTime;
                createdOn = program.CreationTime;
                megaBytes = program.Length / 1048576d;
            }

            return new ProgramInfo(fileName, lastModified, createdOn, Math.Round(megaBytes, 2));
        }

        //
        // PcaClient Viewer Codigo
        //
        [DllImport("Kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
    int dwDesitedAccess,
    bool bInheritHandle,
    int dwProcessID);

        [DllImport("kernel32.dll")]
        static extern int VirtualQueryEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            out MEMORY_BASIC_INFORMATION lpBuffer,
            uint dwLength);

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            IntPtr dwSize,
            ref int lpNumberOfBytesRead);

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        const int PROCESS_ALL_ACCESS = (0x1F0FFF);
        const int MEM_COMMIT = (0x00001000);
        const int MEM_FREE = (0x00010000);
        const int MEM_PRIVATE = (0x00020000);
        const int MEM_IMAGE = (0x01000000);
        const int MEM_MAPPED = (0x00040000);
        const int PAGE_NOACCESS = (0x01);

        static void PcaSvc(string[] args)
        {
            List<string> dump = new List<string>();
            int pid = Process.GetProcessesByName("explorer").FirstOrDefault().Id;
            MEMORY_BASIC_INFORMATION memInfo = new MEMORY_BASIC_INFORMATION();
            IntPtr hProc = OpenProcess(PROCESS_ALL_ACCESS, true, pid);
            int memInfoSize = Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
            byte first = 0, second = 0;
            bool uFlag = true, isUnicode = false;

            Console.ForegroundColor = ConsoleColor.White;

            for (IntPtr p = IntPtr.Zero;
                VirtualQueryEx(hProc, p, out memInfo,
                (uint)memInfoSize) == memInfoSize;
                p = new IntPtr(p.ToInt64() + memInfo.RegionSize.ToInt64()))
            {

                if (memInfo.Protect == PAGE_NOACCESS) continue;

                if (memInfo.State == MEM_COMMIT
                    && memInfo.Type == MEM_PRIVATE)
                {
                    byte[] buffer = new byte[memInfo.RegionSize.ToInt64()];
                    int bytesRead = 0;

                    if (ReadProcessMemory(hProc, p, buffer, memInfo.RegionSize, ref bytesRead))
                    {
                        Array.Resize(ref buffer, bytesRead);
                        StringBuilder builder = new StringBuilder();

                        for (int i = 0; i < bytesRead; i++)
                        {
                            bool cFlag = isChar(buffer[i]);

                            if (cFlag && uFlag && isUnicode && first > 0)
                            {
                                isUnicode = false;
                                if (builder.Length > 0) builder.Remove(builder.Length - 1, 1);
                                builder.Append((char)buffer[i]);
                            }
                            else if (cFlag) builder.Append((char)buffer[i]);
                            else if (uFlag && buffer[i] == 0 && isChar(first) && isChar(second))
                                isUnicode = true;
                            else if (uFlag && buffer[i] == 0 && isChar(first)
                                && isChar(second) && builder.Length < 5)
                            {
                                isUnicode = true;
                                builder = new StringBuilder();
                                builder.Append((char)first);
                            }
                            else
                            {
                                if (builder.Length >= 5 && builder.Length <= 1500)
                                {
                                    int l = builder.Length;
                                    if (isUnicode) l *= 2;
                                    dump.Add(builder.ToString());
                                }

                                isUnicode = false;
                                builder = new StringBuilder();
                            }
                        }
                    }
                }

            }

            Regex rgx = new Regex(@"^TRACE,.+,PcaClient,.+,(\w:\\.+.exe).+$", RegexOptions.Multiline);

            Console.WriteLine("PcaClient\n-----------------------\n");
            foreach (string d in dump)
            {
                MatchCollection matches = rgx.Matches(d);
                foreach (Match match in matches)
                    Console.WriteLine(match.Groups[1].Value);
            }

            Console.Write("\n\nPress ENTER to go to the menu...");
            Console.ReadLine();
            Console.Clear();
            Main(args);
         
        }

        static bool isChar(byte b)
        {
            return (b >= 32 && b <= 126) || b == 10 || b == 13 || b == 9;
        }

        static DateTime startTime()
        {
            return DateTime.Now.AddMilliseconds(-Environment.TickCount);
        }
    }
}