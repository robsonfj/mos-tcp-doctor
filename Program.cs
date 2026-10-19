using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Xml;

[assembly: AssemblyTitle("TcpPortDoctor")]
[assembly: AssemblyDescription("Diagnostico de portas TCP e MOS Profile 0 para Windows")]
[assembly: AssemblyCompany("TCP_DOCTOR")]
[assembly: AssemblyProduct("TcpPortDoctor")]
[assembly: AssemblyVersion("1.2.0.0")]
[assembly: AssemblyFileVersion("1.2.0.0")]

namespace TcpPortDoctor
{
    internal enum OperationMode
    {
        Listen,
        Connect,
        MosProfile0Test,
        SelfTest
    }

    internal enum MosCompatibilityMode
    {
        Auto,
        Mos26,
        Mos280,
        Mos281,
        Mos282,
        Mos283,
        Mos284,
        Mos285,
        Mos40
    }

    internal sealed class Options
    {
        public OperationMode Mode = OperationMode.Listen;
        public string BindAddress = "0.0.0.0";
        public string Target = "127.0.0.1";
        public int[] Ports = new int[] { 10540, 10541, 10542 };
        public int DurationSeconds = 60;
        public int TimeoutMilliseconds = 3000;
        public string MosId = "tcp-port-doctor.mos";
        public string NcsId = "tcp-port-doctor.ncs";
        public string DeviceType = "MOS";
        public MosCompatibilityMode MosCompatibility = MosCompatibilityMode.Auto;
        public bool NoPause;
        public bool Help;
        public bool Interactive;
    }

    internal sealed class OpenListener
    {
        public int Port;
        public TcpListener Listener;
        public bool SelfTestPassed;
    }

    internal sealed class MosServerState
    {
        private readonly object sync = new object();
        private readonly List<TcpClient> clients = new List<TcpClient>();

        public volatile bool Stopping;

        public void Add(TcpClient client)
        {
            lock (sync)
            {
                if (Stopping)
                {
                    client.Close();
                    return;
                }
                clients.Add(client);
            }
        }

        public void Remove(TcpClient client)
        {
            lock (sync)
            {
                clients.Remove(client);
            }
        }

        public void StopAll()
        {
            Stopping = true;
            lock (sync)
            {
                foreach (TcpClient client in clients.ToArray())
                {
                    try { client.Close(); } catch { }
                }
                clients.Clear();
            }
        }
    }

    internal sealed class MosMessageReader
    {
        private readonly NetworkStream stream;
        private readonly List<byte> buffer = new List<byte>();
        private Encoding encoding;
        private byte[] delimiter;

        public MosMessageReader(NetworkStream networkStream)
        {
            stream = networkStream;
        }

        public Encoding Encoding
        {
            get { return encoding ?? new UnicodeEncoding(true, false, true); }
        }

        public string EncodingDescription
        {
            get
            {
                if (encoding == null) return "ainda nao detectada";
                if (encoding.CodePage == 1201) return "UTF-16 big-endian (UCS-2 MOS)";
                if (encoding.CodePage == 1200) return "UTF-16 little-endian";
                if (encoding.CodePage == 65001) return "UTF-8";
                return encoding.EncodingName;
            }
        }

        public string ReadNextMessage(MosServerState serverState)
        {
            return ReadNextMessage(serverState, 0);
        }

        public string ReadNextMessage(MosServerState serverState, int timeoutMilliseconds)
        {
            byte[] chunk = new byte[4096];
            Stopwatch stopwatch = Stopwatch.StartNew();
            while (serverState == null || (!serverState.Stopping && !Program.CancelRequested))
            {
                if (timeoutMilliseconds > 0 && stopwatch.ElapsedMilliseconds >= timeoutMilliseconds)
                {
                    throw new TimeoutException("Resposta MOS nao chegou em " + timeoutMilliseconds + " ms.");
                }
                DetectEncoding();
                string extracted = TryExtract();
                if (extracted != null)
                {
                    return extracted;
                }

                int read;
                try
                {
                    read = stream.Read(chunk, 0, chunk.Length);
                }
                catch (IOException exception)
                {
                    SocketException socketException = exception.InnerException as SocketException;
                    if (socketException != null && socketException.SocketErrorCode == SocketError.TimedOut)
                    {
                        if (timeoutMilliseconds > 0 && stopwatch.ElapsedMilliseconds >= timeoutMilliseconds)
                        {
                            throw new TimeoutException("Resposta MOS nao chegou em " + timeoutMilliseconds + " ms.");
                        }
                        continue;
                    }
                    throw;
                }

                if (read == 0)
                {
                    return null;
                }
                for (int index = 0; index < read; index++)
                {
                    buffer.Add(chunk[index]);
                }
                if (buffer.Count > 1024 * 1024)
                {
                    throw new InvalidDataException("Mensagem MOS excedeu o limite de 1 MiB do diagnostico.");
                }
            }
            return null;
        }

        private void DetectEncoding()
        {
            if (buffer.Count >= 4 &&
                ((buffer[0] == (byte)'P' && buffer[1] == (byte)'O' && buffer[2] == (byte)'S' && buffer[3] == (byte)'T') ||
                 (buffer[0] == (byte)'G' && buffer[1] == (byte)'E' && buffer[2] == (byte)'T' && buffer[3] == (byte)' ')))
            {
                throw new InvalidDataException("Trafego HTTP/SOAP detectado. MOS 3.x Profile 0 usa Web Services HTTP, nao o transporte socket MOS 2.x/4.0 deste listener.");
            }
            if (encoding != null || buffer.Count < 2)
            {
                return;
            }

            if (buffer[0] == 0xFE && buffer[1] == 0xFF)
            {
                encoding = new UnicodeEncoding(true, true, true);
            }
            else if (buffer[0] == 0xFF && buffer[1] == 0xFE)
            {
                encoding = new UnicodeEncoding(false, true, true);
            }
            else if (buffer[0] == 0x00 && buffer[1] == 0x3C)
            {
                encoding = new UnicodeEncoding(true, false, true);
            }
            else if (buffer[0] == 0x3C && buffer[1] == 0x00)
            {
                encoding = new UnicodeEncoding(false, false, true);
            }
            else
            {
                encoding = new UTF8Encoding(false, true);
            }
            delimiter = encoding.GetBytes("</mos>");
        }

        private string TryExtract()
        {
            if (encoding == null || delimiter == null || buffer.Count < delimiter.Length)
            {
                return null;
            }

            int delimiterIndex = IndexOf(buffer, delimiter);
            if (delimiterIndex < 0)
            {
                return null;
            }

            int byteCount = delimiterIndex + delimiter.Length;
            byte[] messageBytes = buffer.GetRange(0, byteCount).ToArray();
            buffer.RemoveRange(0, byteCount);
            string message = encoding.GetString(messageBytes);
            return message.Trim().TrimStart('\uFEFF');
        }

        private static int IndexOf(List<byte> bytes, byte[] pattern)
        {
            for (int index = 0; index <= bytes.Count - pattern.Length; index++)
            {
                bool match = true;
                for (int patternIndex = 0; patternIndex < pattern.Length; patternIndex++)
                {
                    if (bytes[index + patternIndex] != pattern[patternIndex])
                    {
                        match = false;
                        break;
                    }
                }
                if (match) return index;
            }
            return -1;
        }
    }

    internal static class Log
    {
        private static StreamWriter writer;
        private static readonly object Sync = new object();

        public static string FilePath { get; private set; }

        public static void Initialize()
        {
            string baseDirectory = AppDomain.CurrentDomain.BaseDirectory;
            string logDirectory = Path.Combine(baseDirectory, "logs");

            try
            {
                Directory.CreateDirectory(logDirectory);
            }
            catch
            {
                logDirectory = Path.Combine(Path.GetTempPath(), "TcpPortDoctor-logs");
                Directory.CreateDirectory(logDirectory);
            }

            FilePath = Path.Combine(logDirectory, "TcpPortDoctor_" + DateTime.Now.ToString("yyyyMMdd_HHmmss_fff") + ".log");
            writer = new StreamWriter(FilePath, false, new UTF8Encoding(true));
            writer.AutoFlush = true;
        }

        public static void Close()
        {
            lock (Sync)
            {
                if (writer != null)
                {
                    writer.Dispose();
                    writer = null;
                }
            }
        }

        public static void Info(string message)
        {
            Write("INFO ", message);
        }

        public static void Ok(string message)
        {
            Write("OK   ", message);
        }

        public static void Warn(string message)
        {
            Write("AVISO", message);
        }

        public static void Error(string message)
        {
            Write("ERRO ", message);
        }

        public static void Section(string title)
        {
            Write("-----", "");
            Write("-----", "==== " + title + " ====");
        }

        public static void Raw(string message)
        {
            lock (Sync)
            {
                string line = "             " + message;
                Console.WriteLine(line);
                if (writer != null)
                {
                    writer.WriteLine(line);
                }
            }
        }

        private static void Write(string level, string message)
        {
            lock (Sync)
            {
                string line = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff") + " [" + level + "] " + message;
                Console.WriteLine(line);
                if (writer != null)
                {
                    writer.WriteLine(line);
                }
            }
        }
    }

    internal static class Program
    {
        private static volatile bool cancelRequested;
        private static int messageSequence = Environment.TickCount & 0x3FFFFFFF;

        public static bool CancelRequested
        {
            get { return cancelRequested; }
        }

        private static int Main(string[] args)
        {
            int exitCode = 1;
            bool shouldPause = false;

            try
            {
                try
                {
                    Console.OutputEncoding = Encoding.UTF8;
                }
                catch
                {
                    // Alguns hosts antigos nao permitem alterar a codificacao do console.
                }

                Log.Initialize();
                Console.CancelKeyPress += delegate(object sender, ConsoleCancelEventArgs eventArgs)
                {
                    eventArgs.Cancel = true;
                    cancelRequested = true;
                    Log.Warn("Ctrl+C recebido; encerrando os testes com seguranca...");
                };

                PrintBanner();
                Log.Info("Arquivo de log: " + Log.FilePath);

                Options options;
                string parseError;
                if (!TryParseOptions(args, out options, out parseError))
                {
                    Log.Error(parseError);
                    PrintUsage();
                    return 2;
                }

                if (options.Help)
                {
                    PrintUsage();
                    return 0;
                }

                if (options.Interactive)
                {
                    ConfigureInteractively(options);
                }

                shouldPause = !options.NoPause && !Console.IsInputRedirected;

                PrintConfiguration(options);
                CollectSystemDiagnostics(options.Ports);

                if (options.Mode == OperationMode.Listen)
                {
                    exitCode = RunListenTest(options);
                }
                else if (options.Mode == OperationMode.Connect)
                {
                    exitCode = RunConnectTest(options);
                }
                else if (options.Mode == OperationMode.MosProfile0Test)
                {
                    exitCode = RunMosProfile0Test(options);
                }
                else
                {
                    exitCode = RunCompatibilitySelfTest(options);
                }

                Log.Section("RESULTADO FINAL");
                if (exitCode == 0)
                {
                    Log.Ok("Todos os testes solicitados passaram.");
                }
                else
                {
                    Log.Error("Um ou mais testes falharam. Consulte as mensagens acima e o arquivo de log.");
                }

                Log.Info("Log completo salvo em: " + Log.FilePath);
                return exitCode;
            }
            catch (Exception exception)
            {
                try
                {
                    Log.Error("Falha inesperada: " + exception);
                }
                catch
                {
                    Console.Error.WriteLine(exception);
                }
                return 1;
            }
            finally
            {
                if (shouldPause)
                {
                    Console.WriteLine();
                    Console.Write("Pressione ENTER para fechar...");
                    try
                    {
                        Console.ReadLine();
                    }
                    catch
                    {
                    }
                }
                Log.Close();
            }
        }

        private static void PrintBanner()
        {
            Console.WriteLine("============================================================");
            Console.WriteLine(" TcpPortDoctor 1.2 - TCP + MOS Profile 0 no Windows");
            Console.WriteLine("============================================================");
        }

        private static bool TryParseOptions(string[] args, out Options options, out string error)
        {
            options = new Options();
            error = null;
            bool portsSpecified = false;

            if (args.Length == 0)
            {
                options.Interactive = !Console.IsInputRedirected;
                return true;
            }

            options.NoPause = true;

            for (int index = 0; index < args.Length; index++)
            {
                string argument = args[index];
                string value;

                if (argument == "--help" || argument == "-h" || argument == "/?")
                {
                    options.Help = true;
                }
                else if (argument == "--listen")
                {
                    options.Mode = OperationMode.Listen;
                }
                else if (argument == "--connect")
                {
                    if (!TryTakeValue(args, ref index, argument, out value, out error))
                    {
                        return false;
                    }
                    options.Mode = OperationMode.Connect;
                    options.Target = value;
                }
                else if (argument == "--mos-test")
                {
                    if (!TryTakeValue(args, ref index, argument, out value, out error))
                    {
                        return false;
                    }
                    options.Mode = OperationMode.MosProfile0Test;
                    options.Target = value;
                }
                else if (argument == "--mos-server")
                {
                    options.Mode = OperationMode.Listen;
                }
                else if (argument == "--self-test")
                {
                    options.Mode = OperationMode.SelfTest;
                }
                else if (argument == "--bind")
                {
                    if (!TryTakeValue(args, ref index, argument, out value, out error))
                    {
                        return false;
                    }
                    options.BindAddress = value;
                }
                else if (argument == "--ports")
                {
                    if (!TryTakeValue(args, ref index, argument, out value, out error))
                    {
                        return false;
                    }
                    int[] ports;
                    if (!TryParsePorts(value, out ports, out error))
                    {
                        return false;
                    }
                    options.Ports = ports;
                    portsSpecified = true;
                }
                else if (argument == "--seconds")
                {
                    if (!TryTakeValue(args, ref index, argument, out value, out error))
                    {
                        return false;
                    }
                    int seconds;
                    if (!int.TryParse(value, out seconds) || seconds < 0 || seconds > 86400)
                    {
                        error = "Valor invalido para --seconds. Use de 0 a 86400; zero aguarda Ctrl+C.";
                        return false;
                    }
                    options.DurationSeconds = seconds;
                }
                else if (argument == "--timeout")
                {
                    if (!TryTakeValue(args, ref index, argument, out value, out error))
                    {
                        return false;
                    }
                    int timeout;
                    if (!int.TryParse(value, out timeout) || timeout < 100 || timeout > 120000)
                    {
                        error = "Valor invalido para --timeout. Use de 100 a 120000 milissegundos.";
                        return false;
                    }
                    options.TimeoutMilliseconds = timeout;
                }
                else if (argument == "--mos-id")
                {
                    if (!TryTakeValue(args, ref index, argument, out value, out error))
                    {
                        return false;
                    }
                    options.MosId = value;
                }
                else if (argument == "--ncs-id")
                {
                    if (!TryTakeValue(args, ref index, argument, out value, out error))
                    {
                        return false;
                    }
                    options.NcsId = value;
                }
                else if (argument == "--device-type")
                {
                    if (!TryTakeValue(args, ref index, argument, out value, out error))
                    {
                        return false;
                    }
                    value = value.ToUpperInvariant();
                    if (value != "MOS" && value != "NCS")
                    {
                        error = "Valor invalido para --device-type. Use MOS ou NCS.";
                        return false;
                    }
                    options.DeviceType = value;
                }
                else if (argument == "--mos-version")
                {
                    if (!TryTakeValue(args, ref index, argument, out value, out error))
                    {
                        return false;
                    }
                    if (!TryParseMosCompatibility(value, out options.MosCompatibility))
                    {
                        error = "Valor invalido para --mos-version. Use auto, 2.6, 2.8.0, 2.8.1, 2.8.2, 2.8.3, 2.8.4, 2.8.5 ou 4.0.";
                        return false;
                    }
                }
                else if (argument == "--pause")
                {
                    options.NoPause = false;
                }
                else if (argument == "--no-pause")
                {
                    options.NoPause = true;
                }
                else
                {
                    error = "Argumento desconhecido: " + argument;
                    return false;
                }
            }

            if (options.Mode == OperationMode.MosProfile0Test && !portsSpecified)
            {
                options.Ports = new int[] { 10540, 10541 };
            }

            return true;
        }

        private static bool TryParseMosCompatibility(string value, out MosCompatibilityMode mode)
        {
            string normalized = (value ?? "").Trim().ToLowerInvariant();
            if (normalized == "auto") mode = MosCompatibilityMode.Auto;
            else if (normalized == "2.6" || normalized == "26") mode = MosCompatibilityMode.Mos26;
            else if (normalized == "2.8.0" || normalized == "2.8") mode = MosCompatibilityMode.Mos280;
            else if (normalized == "2.8.1" || normalized == "2.8-legacy" || normalized == "28-legacy") mode = MosCompatibilityMode.Mos281;
            else if (normalized == "2.8.2") mode = MosCompatibilityMode.Mos282;
            else if (normalized == "2.8.3") mode = MosCompatibilityMode.Mos283;
            else if (normalized == "2.8.4") mode = MosCompatibilityMode.Mos284;
            else if (normalized == "2.8.5" || normalized == "2.8-modern" || normalized == "28-modern") mode = MosCompatibilityMode.Mos285;
            else if (normalized == "4.0" || normalized == "40" || normalized == "4") mode = MosCompatibilityMode.Mos40;
            else
            {
                mode = MosCompatibilityMode.Auto;
                return false;
            }
            return true;
        }

        private static bool TryTakeValue(string[] args, ref int index, string argument, out string value, out string error)
        {
            value = null;
            error = null;
            if (index + 1 >= args.Length)
            {
                error = "O argumento " + argument + " exige um valor.";
                return false;
            }
            index++;
            value = args[index];
            return true;
        }

        private static bool TryParsePorts(string text, out int[] ports, out string error)
        {
            error = null;
            List<int> result = new List<int>();
            string[] parts = text.Split(new char[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string part in parts)
            {
                int port;
                if (!int.TryParse(part.Trim(), out port) || port < 1 || port > 65535)
                {
                    ports = null;
                    error = "Porta invalida: " + part + ". Use numeros entre 1 e 65535.";
                    return false;
                }
                if (!result.Contains(port))
                {
                    result.Add(port);
                }
            }

            if (result.Count == 0)
            {
                ports = null;
                error = "Informe pelo menos uma porta.";
                return false;
            }

            ports = result.ToArray();
            return true;
        }

        private static void ConfigureInteractively(Options options)
        {
            Log.Section("CONFIGURACAO INTERATIVA");
            Console.WriteLine("1 - Escutar/abrir portas nesta maquina (padrao)");
            Console.WriteLine("2 - Conectar e testar portas de outra maquina");
            Console.WriteLine("3 - Validar MOS Profile 0 em outra maquina");
            Console.Write("Escolha [1]: ");
            string mode = Console.ReadLine();

            if (mode != null && (mode.Trim() == "2" || mode.Trim() == "3"))
            {
                options.Mode = mode.Trim() == "3" ? OperationMode.MosProfile0Test : OperationMode.Connect;
                if (options.Mode == OperationMode.MosProfile0Test)
                {
                    options.Ports = new int[] { 10540, 10541 };
                }
                Console.Write("Nome ou IP da maquina alvo [127.0.0.1]: ");
                string target = Console.ReadLine();
                if (!String.IsNullOrWhiteSpace(target))
                {
                    options.Target = target.Trim();
                }
            }
            else
            {
                options.Mode = OperationMode.Listen;
                PrintLocalAddressSummary();
                Console.Write("IP LOCAL para bind [0.0.0.0 = todos os IPv4]: ");
                string bindAddress = Console.ReadLine();
                if (!String.IsNullOrWhiteSpace(bindAddress))
                {
                    options.BindAddress = bindAddress.Trim();
                }

                Console.Write("Tempo de escuta em segundos [60; 0 = ate Ctrl+C]: ");
                string secondsText = Console.ReadLine();
                int seconds;
                if (!String.IsNullOrWhiteSpace(secondsText) && int.TryParse(secondsText, out seconds) && seconds >= 0 && seconds <= 86400)
                {
                    options.DurationSeconds = seconds;
                }
            }

            string defaultPorts = options.Mode == OperationMode.MosProfile0Test ? "10540,10541" : "10540,10541,10542";
            Console.Write("Portas separadas por virgula [" + defaultPorts + "]: ");
            string portsText = Console.ReadLine();
            if (!String.IsNullOrWhiteSpace(portsText))
            {
                int[] ports;
                string error;
                if (TryParsePorts(portsText, out ports, out error))
                {
                    options.Ports = ports;
                }
                else
                {
                    Log.Warn(error + " Usando as portas padrao.");
                }
            }
        }

        private static void PrintUsage()
        {
            Console.WriteLine();
            Console.WriteLine("USO:");
            Console.WriteLine("  TcpPortDoctor.exe");
            Console.WriteLine("      Abre o menu interativo.");
            Console.WriteLine();
            Console.WriteLine("  TcpPortDoctor.exe --listen [--bind IP] [--ports LISTA] [--seconds N]");
            Console.WriteLine("      Tenta fazer bind e escutar nesta maquina.");
            Console.WriteLine();
            Console.WriteLine("  TcpPortDoctor.exe --connect HOST [--ports LISTA] [--timeout MS]");
            Console.WriteLine("      Testa conexao ate outra maquina.");
            Console.WriteLine();
            Console.WriteLine("  TcpPortDoctor.exe --mos-test HOST [--ports LISTA] [--timeout MS]");
            Console.WriteLine("      Envia keepAlive, heartbeat e reqMachInfo; valida heartbeat e listMachInfo.");
            Console.WriteLine();
            Console.WriteLine("  TcpPortDoctor.exe --self-test");
            Console.WriteLine("      Valida internamente todas as variantes de compatibilidade do Profile 0.");
            Console.WriteLine();
            Console.WriteLine("OPCOES:");
            Console.WriteLine("  --bind IP       IP local; padrao 0.0.0.0 (todas as interfaces IPv4)");
            Console.WriteLine("  --ports LISTA   Padrao 10540,10541,10542");
            Console.WriteLine("                   No modo --mos-test, padrao 10540,10541");
            Console.WriteLine("  --seconds N     Tempo de escuta; 0 = ate Ctrl+C; padrao 60");
            Console.WriteLine("  --timeout MS    Timeout por conexao; padrao 3000");
            Console.WriteLine("  --mos-id ID     Identificador MOS usado nos XMLs");
            Console.WriteLine("  --ncs-id ID     Identificador NCS usado nos XMLs");
            Console.WriteLine("  --device-type   Tipo anunciado no listMachInfo: MOS ou NCS");
            Console.WriteLine("  --mos-version   auto (padrao), 2.6, 2.8.0 ... 2.8.5 ou 4.0");
            Console.WriteLine("  --pause          Aguarda ENTER no fim");
            Console.WriteLine("  --no-pause       Nao aguarda ENTER no fim");
            Console.WriteLine("  --help            Mostra esta ajuda");
            Console.WriteLine();
            Console.WriteLine("EXEMPLOS:");
            Console.WriteLine("  TcpPortDoctor.exe --listen --bind 0.0.0.0 --seconds 120 --pause");
            Console.WriteLine("  TcpPortDoctor.exe --listen --bind 192.168.1.50 --ports 10540,10541,10542");
            Console.WriteLine("  TcpPortDoctor.exe --connect 192.168.1.50 --ports 10540,10541,10542");
            Console.WriteLine("  TcpPortDoctor.exe --mos-test 192.168.1.50 --ports 10540,10541");
            Console.WriteLine("  TcpPortDoctor.exe --listen --mos-version 2.8-legacy --seconds 120");
            Console.WriteLine("  TcpPortDoctor.exe --self-test");
        }

        private static void PrintConfiguration(Options options)
        {
            Log.Section("CONFIGURACAO EFETIVA");
            string modeDescription = options.Mode == OperationMode.Listen ? "SERVIDOR MOS PROFILE 0 / BIND" :
                (options.Mode == OperationMode.Connect ? "CONECTAR TCP" :
                (options.Mode == OperationMode.MosProfile0Test ? "CLIENTE DE TESTE MOS PROFILE 0" : "AUTOTESTE DE COMPATIBILIDADE"));
            Log.Info("Modo: " + modeDescription);
            Log.Info("Portas: " + String.Join(", ", options.Ports.Select(delegate(int port) { return port.ToString(); }).ToArray()));
            if (options.Mode == OperationMode.Listen)
            {
                Log.Info("Endereco solicitado para bind: " + options.BindAddress);
                Log.Info("Duracao da escuta: " + (options.DurationSeconds == 0 ? "ate Ctrl+C" : options.DurationSeconds + " segundo(s)"));
            }
            else
            {
                Log.Info("Maquina alvo: " + options.Target);
                Log.Info("Timeout por porta: " + options.TimeoutMilliseconds + " ms");
            }
            if (options.Mode == OperationMode.Listen || options.Mode == OperationMode.MosProfile0Test)
            {
                Log.Info("MOS ID: " + options.MosId + "; NCS ID: " + options.NcsId + "; deviceType: " + options.DeviceType);
                Log.Info("Compatibilidade MOS: " + MosCompatibilityName(options.MosCompatibility));
            }
        }

        private static void CollectSystemDiagnostics(int[] ports)
        {
            Log.Section("AMBIENTE");
            Log.Info("Data/hora local: " + DateTime.Now.ToString("O"));
            Log.Info("Data/hora UTC: " + DateTime.UtcNow.ToString("O"));
            Log.Info("Maquina: " + Environment.MachineName);
            Log.Info("Usuario: " + Environment.UserDomainName + "\\" + Environment.UserName);
            Log.Info("Sistema operacional: " + Environment.OSVersion);
            Log.Info("Processo 64 bits: " + Environment.Is64BitProcess + "; SO 64 bits: " + Environment.Is64BitOperatingSystem);
            Log.Info(".NET em uso: " + Environment.Version);
            Log.Info("Diretorio do executavel: " + AppDomain.CurrentDomain.BaseDirectory);
            Log.Info("Elevado/Administrador: " + IsAdministrator());
            Log.Info("Observacao: portas acima de 1024 normalmente nao exigem Administrador para bind.");

            PrintLocalAddressSummary();
            PrintNetworkInterfaces();
            PrintExistingTcpState(ports);

            if (Environment.OSVersion.Platform == PlatformID.Win32NT)
            {
                Log.Section("FIREWALL E RESERVAS DO WINDOWS (SOMENTE LEITURA)");
                RunAndLogCommand("netsh.exe", "advfirewall show allprofiles state", 15000);
                RunAndLogCommand("netsh.exe", "int ipv4 show excludedportrange protocol=tcp", 15000);
                RunAndLogCommand("netsh.exe", "int ipv6 show excludedportrange protocol=tcp", 15000);
                PrintFirewallRegistryState();
                PrintMatchingFirewallRules(ports);
            }
        }

        private static bool IsAdministrator()
        {
            try
            {
                WindowsIdentity identity = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        private static void PrintLocalAddressSummary()
        {
            Log.Section("ENDERECOS LOCAIS");
            try
            {
                Log.Info("Nome DNS local: " + Dns.GetHostName());
                IPAddress[] addresses = Dns.GetHostAddresses(Dns.GetHostName());
                if (addresses.Length == 0)
                {
                    Log.Warn("O nome local nao resolveu nenhum endereco.");
                }
                foreach (IPAddress address in addresses)
                {
                    Log.Info("Endereco local resolvido: " + address + " (" + address.AddressFamily + ")");
                }
                Log.Info("0.0.0.0 significa todas as interfaces IPv4; nao e um endereco para clientes usarem.");
            }
            catch (Exception exception)
            {
                Log.Warn("Nao foi possivel resolver os enderecos locais: " + exception.Message);
            }
        }

        private static void PrintNetworkInterfaces()
        {
            Log.Section("INTERFACES DE REDE");
            try
            {
                NetworkInterface[] interfaces = NetworkInterface.GetAllNetworkInterfaces();
                foreach (NetworkInterface networkInterface in interfaces)
                {
                    Log.Info("Interface: " + networkInterface.Name + " | " + networkInterface.NetworkInterfaceType + " | " + networkInterface.OperationalStatus + " | " + networkInterface.Description);
                    try
                    {
                        IPInterfaceProperties properties = networkInterface.GetIPProperties();
                        foreach (UnicastIPAddressInformation address in properties.UnicastAddresses)
                        {
                            Log.Raw("IP: " + address.Address + " | mascara/prefixo: " + (address.IPv4Mask == null ? "n/d" : address.IPv4Mask.ToString()));
                        }
                        foreach (GatewayIPAddressInformation gateway in properties.GatewayAddresses)
                        {
                            Log.Raw("Gateway: " + gateway.Address);
                        }
                    }
                    catch (Exception exception)
                    {
                        Log.Raw("Detalhes indisponiveis: " + exception.Message);
                    }
                }
            }
            catch (Exception exception)
            {
                Log.Warn("Nao foi possivel enumerar interfaces: " + exception.Message);
            }
        }

        private static void PrintExistingTcpState(int[] ports)
        {
            Log.Section("USO ATUAL DAS PORTAS");
            HashSet<int> wanted = new HashSet<int>(ports);
            bool found = false;

            try
            {
                IPGlobalProperties properties = IPGlobalProperties.GetIPGlobalProperties();
                foreach (IPEndPoint listener in properties.GetActiveTcpListeners())
                {
                    if (wanted.Contains(listener.Port))
                    {
                        found = true;
                        Log.Warn("Ja existe um listener TCP em " + listener + ". O novo bind pode falhar com porta em uso.");
                    }
                }

                foreach (TcpConnectionInformation connection in properties.GetActiveTcpConnections())
                {
                    if (wanted.Contains(connection.LocalEndPoint.Port) || wanted.Contains(connection.RemoteEndPoint.Port))
                    {
                        found = true;
                        Log.Info("Conexao existente: " + connection.LocalEndPoint + " -> " + connection.RemoteEndPoint + " | " + connection.State);
                    }
                }
            }
            catch (Exception exception)
            {
                Log.Warn("Nao foi possivel consultar o estado TCP via .NET: " + exception.Message);
            }

            string netstat = CaptureCommand("netstat.exe", "-ano -p tcp", 15000);
            if (!String.IsNullOrWhiteSpace(netstat))
            {
                string[] lines = netstat.Split(new string[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
                HashSet<int> processIds = new HashSet<int>();
                foreach (string line in lines)
                {
                    if (LineMentionsPort(line, ports))
                    {
                        found = true;
                        Log.Info("netstat: " + line.Trim());
                        int processId;
                        if (TryGetLastInteger(line, out processId))
                        {
                            processIds.Add(processId);
                        }
                    }
                }

                foreach (int processId in processIds)
                {
                    try
                    {
                        Process process = Process.GetProcessById(processId);
                        Log.Info("PID " + processId + " = " + process.ProcessName);
                    }
                    catch (Exception exception)
                    {
                        Log.Info("PID " + processId + " sem nome acessivel: " + exception.Message);
                    }
                }
            }

            if (!found)
            {
                Log.Ok("Nenhum listener ou conexao atual foi encontrado nas portas solicitadas.");
            }
        }

        private static bool LineMentionsPort(string line, int[] ports)
        {
            foreach (int port in ports)
            {
                string marker = ":" + port;
                int start = 0;
                while (true)
                {
                    int index = line.IndexOf(marker, start, StringComparison.Ordinal);
                    if (index < 0)
                    {
                        break;
                    }
                    int after = index + marker.Length;
                    if (after == line.Length || !Char.IsDigit(line[after]))
                    {
                        return true;
                    }
                    start = after;
                }
            }
            return false;
        }

        private static bool TryGetLastInteger(string line, out int value)
        {
            string[] fields = line.Split(new char[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length == 0)
            {
                value = 0;
                return false;
            }
            return int.TryParse(fields[fields.Length - 1], out value);
        }

        private static void PrintMatchingFirewallRules(int[] ports)
        {
            string quotedPorts = String.Join(",", ports.Select(delegate(int port) { return "'" + port + "'"; }).ToArray());
            string script = "$ErrorActionPreference='Stop'; " +
                "$ports=@(" + quotedPorts + "); " +
                "$items=@(Get-NetFirewallPortFilter | " +
                "Where-Object { $_.Protocol -eq 'TCP' -and $ports -contains [string]$_.LocalPort } | " +
                "ForEach-Object { $f=$_; $rules=@(Get-NetFirewallRule -AssociatedNetFirewallPortFilter $f -ErrorAction SilentlyContinue); " +
                "foreach($r in $rules){ [PSCustomObject]@{Regra=$r.DisplayName;Habilitada=$r.Enabled;Direcao=$r.Direction;Acao=$r.Action;Perfil=$r.Profile;Porta=$f.LocalPort} } }); " +
                "if($items.Count -eq 0){'Nenhuma regra de entrada TCP especifica encontrada para as portas.'}else{$items | Format-Table -AutoSize | Out-String -Width 300}";
            RunAndLogCommand("powershell.exe", "-NoLogo -NoProfile -NonInteractive -Command \"" + script + "\"", 15000);
        }

        private static void PrintFirewallRegistryState()
        {
            string root = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\";
            string[] profiles = new string[] { "DomainProfile", "StandardProfile", "PublicProfile" };
            foreach (string profile in profiles)
            {
                try
                {
                    using (Microsoft.Win32.RegistryKey key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(root + profile))
                    {
                        if (key == null)
                        {
                            Log.Warn("Perfil de Firewall nao encontrado no Registro: " + profile);
                            continue;
                        }
                        object enabled = key.GetValue("EnableFirewall", "nao definido");
                        object inbound = key.GetValue("DefaultInboundAction", "nao definido");
                        object outbound = key.GetValue("DefaultOutboundAction", "nao definido");
                        Log.Info("Firewall/Registro " + profile + ": EnableFirewall=" + enabled + "; DefaultInboundAction=" + inbound + "; DefaultOutboundAction=" + outbound);
                    }
                }
                catch (Exception exception)
                {
                    Log.Warn("Nao foi possivel ler o perfil " + profile + " no Registro: " + exception.Message);
                }
            }
        }

        private static int RunListenTest(Options options)
        {
            Log.Section("TESTE DE BIND/ESCUTA");
            Log.Info("Este teste NAO altera o Firewall do Windows. Ele abre sockets enquanto o programa estiver rodando.");
            Log.Info("Para testar entrada pela rede, deixe este programa escutando e execute --connect a partir de outra maquina.");
            Log.Info("O listener interpreta MOS Profile 0: keepAlive, heartbeat, reqMachInfo e listMachInfo.");
            Log.Info("Respostas MOS usam a mesma codificacao recebida; o padrao oficial e UCS-2/UTF-16 big-endian.");

            IPAddress bindAddress;
            try
            {
                bindAddress = ResolveAddress(options.BindAddress, true);
            }
            catch (Exception exception)
            {
                Log.Error("Nao foi possivel resolver o endereco de bind '" + options.BindAddress + "': " + exception.Message);
                return 1;
            }

            Log.Info("Endereco selecionado para bind: " + bindAddress + " (" + bindAddress.AddressFamily + ")");
            if (!IsLocalAddress(bindAddress))
            {
                Log.Error("O endereco " + bindAddress + " nao pertence a esta maquina. Um processo nao pode fazer bind no IP de outro computador.");
                Log.Info("Execute este EXE na maquina dona desse IP, ou use --connect " + options.BindAddress + " para testar a conexao ate ela.");
                return 1;
            }

            List<OpenListener> openListeners = new List<OpenListener>();
            int failures = 0;

            foreach (int port in options.Ports)
            {
                TcpListener listener = null;
                try
                {
                    listener = new TcpListener(bindAddress, port);
                    listener.Server.ExclusiveAddressUse = true;
                    listener.Start(100);
                    OpenListener openListener = new OpenListener();
                    openListener.Port = port;
                    openListener.Listener = listener;
                    openListeners.Add(openListener);
                    Log.Ok("BIND OK: escutando em " + listener.LocalEndpoint + " | ExclusiveAddressUse=true | backlog=100");
                }
                catch (SocketException exception)
                {
                    failures++;
                    if (listener != null)
                    {
                        try { listener.Stop(); } catch { }
                    }
                    LogSocketFailure("BIND", bindAddress + ":" + port, exception);
                }
                catch (Exception exception)
                {
                    failures++;
                    if (listener != null)
                    {
                        try { listener.Stop(); } catch { }
                    }
                    Log.Error("BIND FALHOU em " + bindAddress + ":" + port + " | " + exception);
                }
            }

            foreach (OpenListener openListener in openListeners)
            {
                IPAddress testAddress = GetSelfTestAddress(bindAddress);
                openListener.SelfTestPassed = TryConnect(testAddress.ToString(), openListener.Port, options.TimeoutMilliseconds, "AUTOTESTE LOCAL");
                if (!openListener.SelfTestPassed)
                {
                    failures++;
                }
            }

            if (openListeners.Count > 0)
            {
                Log.Section("MONITOR DE CONEXOES RECEBIDAS");
                if (options.DurationSeconds == 0)
                {
                    Log.Info("Listeners ativos ate Ctrl+C.");
                }
                else
                {
                    Log.Info("Listeners ativos por " + options.DurationSeconds + " segundo(s).");
                }
                Log.Info("Conexoes serao aceitas e mantidas para processar mensagens MOS Profile 0.");
                MonitorListeners(openListeners, options);
            }

            foreach (OpenListener openListener in openListeners)
            {
                try
                {
                    openListener.Listener.Stop();
                    Log.Info("Listener encerrado: porta " + openListener.Port);
                }
                catch (Exception exception)
                {
                    Log.Warn("Erro ao encerrar listener da porta " + openListener.Port + ": " + exception.Message);
                }
            }

            if (failures == 0 && openListeners.Count == options.Ports.Length)
            {
                Log.Ok("O Windows/.NET permitiu abrir todas as portas e o autoteste local conectou em todas elas.");
                Log.Warn("Isso nao prova acesso vindo de outra maquina. Firewall, roteador, VLAN e NAT ainda podem bloquear trafego externo.");
                PrintFirewallGuidance(options.Ports);
                return 0;
            }

            Log.Error("Falhas no teste de escuta: " + failures + ". Portas abertas com sucesso: " + openListeners.Count + " de " + options.Ports.Length + ".");
            return 1;
        }

        private static void MonitorListeners(List<OpenListener> listeners, Options options)
        {
            Stopwatch stopwatch = Stopwatch.StartNew();
            long nextStatusSecond = 10;
            MosServerState serverState = new MosServerState();

            while (!cancelRequested && (options.DurationSeconds == 0 || stopwatch.Elapsed.TotalSeconds < options.DurationSeconds))
            {
                foreach (OpenListener openListener in listeners)
                {
                    try
                    {
                        while (openListener.Listener.Pending())
                        {
                            TcpClient client = openListener.Listener.AcceptTcpClient();
                            client.ReceiveTimeout = 1000;
                            client.SendTimeout = Math.Max(1000, options.TimeoutMilliseconds);
                            string remote = client.Client.RemoteEndPoint == null ? "desconhecido" : client.Client.RemoteEndPoint.ToString();
                            string local = client.Client.LocalEndPoint == null ? "desconhecido" : client.Client.LocalEndPoint.ToString();
                            Log.Ok("CONEXAO RECEBIDA: remoto=" + remote + " -> local=" + local + " | porta MOS=" + openListener.Port);
                            serverState.Add(client);
                            ThreadPool.QueueUserWorkItem(delegate(object state)
                            {
                                HandleMosClient(client, openListener.Port, options, serverState);
                            });
                        }
                    }
                    catch (SocketException exception)
                    {
                        LogSocketFailure("ACCEPT", "porta " + openListener.Port, exception);
                    }
                    catch (ObjectDisposedException)
                    {
                    }
                }

                if (stopwatch.Elapsed.TotalSeconds >= nextStatusSecond)
                {
                    if (options.DurationSeconds == 0)
                    {
                        Log.Info("Listeners continuam ativos (" + (int)stopwatch.Elapsed.TotalSeconds + " s decorridos)...");
                    }
                    else
                    {
                        int remaining = Math.Max(0, options.DurationSeconds - (int)stopwatch.Elapsed.TotalSeconds);
                        Log.Info("Listeners ativos; aproximadamente " + remaining + " s restantes...");
                    }
                    nextStatusSecond += 10;
                }

                Thread.Sleep(100);
            }
            serverState.StopAll();
        }

        private static void HandleMosClient(TcpClient client, int port, Options options, MosServerState serverState)
        {
            string remote = "desconhecido";
            try
            {
                if (client.Client.RemoteEndPoint != null) remote = client.Client.RemoteEndPoint.ToString();
                NetworkStream stream = client.GetStream();
                MosMessageReader reader = new MosMessageReader(stream);
                DateTime lastHeartbeatResponse = DateTime.MinValue;
                MosCompatibilityMode sessionCompatibility = options.MosCompatibility;

                while (!serverState.Stopping && !cancelRequested && client.Connected)
                {
                    string xml = reader.ReadNextMessage(serverState);
                    if (xml == null) break;

                    Log.Section("MOS RECEBIDO DE " + remote + " NA PORTA " + port);
                    Log.Info("Codificacao detectada: " + reader.EncodingDescription + "; bytes XML completos recebidos.");
                    if (reader.Encoding.CodePage != 1201)
                    {
                        Log.Warn("Codificacao fora do transporte MOS classico: esperado UTF-16 big-endian (UCS-2), recebido " + reader.EncodingDescription + ".");
                    }
                    LogXml(xml);

                    XmlDocument document;
                    try
                    {
                        document = ParseMosXml(xml);
                    }
                    catch (Exception exception)
                    {
                        Log.Error("XML MOS invalido de " + remote + ": " + exception.Message);
                        continue;
                    }

                    XmlElement root = document.DocumentElement;
                    if (root == null || root.Name != "mos")
                    {
                        Log.Error("Mensagem ignorada: elemento raiz deve ser <mos> e tags MOS diferenciam maiusculas/minusculas.");
                        continue;
                    }

                    string requestMosId = GetNodeText(document, "/mos/mosID", options.MosId);
                    string requestNcsId = GetNodeText(document, "/mos/ncsID", options.NcsId);
                    MosCompatibilityMode responseMode = ResolveCompatibility(document, sessionCompatibility);
                    if (sessionCompatibility == MosCompatibilityMode.Auto)
                    {
                        sessionCompatibility = responseMode;
                    }
                    Log.Info("Variante Profile 0 selecionada para a resposta: " + MosCompatibilityName(responseMode) + ".");

                    if (document.SelectSingleNode("/mos/keepAlive") != null || document.SelectSingleNode("/mos/keepalive") != null)
                    {
                        Log.Ok("PROFILE 0 keepAlive valido (incluindo grafia legada); nenhuma resposta sera enviada.");
                        continue;
                    }

                    XmlNode heartbeatNode = document.SelectSingleNode("/mos/heartbeat") ?? document.SelectSingleNode("/mos/heartBeat");
                    if (heartbeatNode != null)
                    {
                        XmlNode timeNode = heartbeatNode.SelectSingleNode("time");
                        string receivedTime = timeNode == null ? "" : timeNode.InnerText.Trim();
                        if (String.IsNullOrWhiteSpace(receivedTime))
                        {
                            Log.Error("heartbeat invalido: elemento <time> obrigatorio ausente ou vazio.");
                            continue;
                        }

                        if (lastHeartbeatResponse != DateTime.MinValue && DateTime.UtcNow.Subtract(lastHeartbeatResponse).TotalSeconds < 5)
                        {
                            Log.Warn("heartbeat recebido logo apos nossa resposta; suprimido para evitar loop infinito entre dois respondedores automaticos.");
                            lastHeartbeatResponse = DateTime.MinValue;
                            continue;
                        }

                        string response = BuildHeartbeat(requestMosId, requestNcsId, responseMode);
                        SendMosXml(stream, response, reader.Encoding, "heartbeat", remote);
                        lastHeartbeatResponse = DateTime.UtcNow;
                        continue;
                    }

                    if (document.SelectSingleNode("/mos/reqMachInfo") != null || document.SelectSingleNode("/mos/reqMachineInfo") != null)
                    {
                        string response = BuildListMachInfo(requestMosId, requestNcsId, options, responseMode);
                        SendMosXml(stream, response, reader.Encoding, "listMachInfo", remote);
                        lastHeartbeatResponse = DateTime.MinValue;
                        continue;
                    }

                    if (document.SelectSingleNode("/mos/listMachInfo") != null)
                    {
                        XmlNode profile = document.SelectSingleNode("/mos/listMachInfo/supportedProfiles/mosProfile[@number='0']") ??
                            document.SelectSingleNode("/mos/listMachInfo/mosProfile0");
                        if (profile != null)
                        {
                            Log.Ok("PROFILE 0 listMachInfo recebido; perfil 0 anunciado como '" + profile.InnerText.Trim() + "'. Nenhuma resposta exigida.");
                        }
                        else
                        {
                            Log.Warn("listMachInfo recebido sem mosProfile number=\"0\".");
                        }
                        lastHeartbeatResponse = DateTime.MinValue;
                        continue;
                    }

                    Log.Warn("XML MOS bem formado, mas nao e uma das quatro mensagens do Profile 0; ignorado sem erro conforme a especificacao.");
                }
            }
            catch (IOException exception)
            {
                if (!serverState.Stopping) Log.Warn("Conexao MOS com " + remote + " terminou por E/S: " + exception.Message);
            }
            catch (SocketException exception)
            {
                if (!serverState.Stopping) LogSocketFailure("SESSAO MOS", remote, exception);
            }
            catch (Exception exception)
            {
                if (!serverState.Stopping) Log.Error("Falha na sessao MOS com " + remote + ": " + exception);
            }
            finally
            {
                serverState.Remove(client);
                try { client.Close(); } catch { }
                Log.Info("CONEXAO MOS ENCERRADA: remoto=" + remote + " | porta=" + port);
            }
        }

        private static int RunMosProfile0Test(Options options)
        {
            Log.Section("VALIDACAO MOS PROFILE 0");
            Log.Info("Fluxo por porta: conecta -> keepAlive (sem resposta) -> heartbeat/heartbeat -> reqMachInfo/listMachInfo.");
            Log.Info("Transmissao do cliente: UTF-16 big-endian sem BOM, conforme o transporte MOS classico.");
            int failures = 0;

            foreach (int port in options.Ports)
            {
                if (port == 10542)
                {
                    Log.Warn("A porta 10542 e destinada a consultas mosReqObjList na especificacao MOS 2.8.5/4.0. O Profile 0 e definido em 10540/10541; o teste sera enviado mesmo assim para diagnostico.");
                }

                if (!TestMosProfile0Port(options, port))
                {
                    failures++;
                }
            }

            if (failures == 0)
            {
                Log.Ok("MOS PROFILE 0 VALIDADO em todas as portas solicitadas: transporte, heartbeat e machine info responderam corretamente.");
                return 0;
            }

            Log.Error("MOS Profile 0 falhou em " + failures + " de " + options.Ports.Length + " porta(s). O log separa falha TCP, timeout, codificacao e XML inesperado.");
            return 1;
        }

        private static bool TestMosProfile0Port(Options options, int port)
        {
            TcpClient client = new TcpClient();
            string endpoint = options.Target + ":" + port;
            try
            {
                Log.Section("MOS PROFILE 0 EM " + endpoint);
                Stopwatch connectWatch = Stopwatch.StartNew();
                IAsyncResult connectResult = client.BeginConnect(options.Target, port, null, null);
                if (!connectResult.AsyncWaitHandle.WaitOne(options.TimeoutMilliseconds, false))
                {
                    Log.Error("MOS TCP FALHOU: " + endpoint + " | TIMEOUT de conexao apos " + options.TimeoutMilliseconds + " ms.");
                    return false;
                }
                client.EndConnect(connectResult);
                connectWatch.Stop();
                client.ReceiveTimeout = Math.Min(1000, options.TimeoutMilliseconds);
                client.SendTimeout = options.TimeoutMilliseconds;
                Log.Ok("MOS TCP OK: " + client.Client.LocalEndPoint + " -> " + client.Client.RemoteEndPoint + " | " + connectWatch.ElapsedMilliseconds + " ms");

                NetworkStream stream = client.GetStream();
                Encoding mosEncoding = new UnicodeEncoding(true, false, true);
                MosMessageReader reader = new MosMessageReader(stream);
                MosCompatibilityMode testMode = options.MosCompatibility == MosCompatibilityMode.Auto ? MosCompatibilityMode.Mos40 : options.MosCompatibility;
                Log.Info("Cliente testara a variante: " + MosCompatibilityName(testMode) + ".");

                if (testMode == MosCompatibilityMode.Mos40)
                {
                    SendMosXml(stream, BuildKeepAlive(options.MosId, options.NcsId), mosEncoding, "keepAlive", endpoint);
                    Log.Ok("keepAlive enviado; nenhuma resposta e esperada pelo MOS 4.0.");
                }

                SendMosXml(stream, BuildHeartbeat(options.MosId, options.NcsId, testMode), mosEncoding, "heartbeat", endpoint);
                string heartbeatXml = reader.ReadNextMessage(null, options.TimeoutMilliseconds);
                Log.Section("MOS RESPOSTA heartbeat DE " + endpoint);
                Log.Info("Codificacao detectada na resposta: " + reader.EncodingDescription);
                LogXml(heartbeatXml);
                XmlDocument heartbeatDocument = ParseMosXml(heartbeatXml);
                if (heartbeatDocument.SelectSingleNode("/mos/heartbeat/time") == null)
                {
                    Log.Error("PROFILE 0 FALHOU: resposta ao heartbeat nao contem /mos/heartbeat/time.");
                    return false;
                }
                Log.Ok("PROFILE 0 heartbeat VALIDADO na porta " + port + ".");

                SendMosXml(stream, BuildReqMachInfo(options.MosId, options.NcsId, testMode), mosEncoding, "reqMachInfo", endpoint);
                string machineInfoXml = reader.ReadNextMessage(null, options.TimeoutMilliseconds);
                Log.Section("MOS RESPOSTA listMachInfo DE " + endpoint);
                Log.Info("Codificacao detectada na resposta: " + reader.EncodingDescription);
                LogXml(machineInfoXml);
                XmlDocument machineInfoDocument = ParseMosXml(machineInfoXml);
                XmlNode listMachInfo = machineInfoDocument.SelectSingleNode("/mos/listMachInfo");
                if (listMachInfo == null)
                {
                    Log.Error("PROFILE 0 FALHOU: resposta a reqMachInfo nao e listMachInfo.");
                    return false;
                }

                XmlNode profile = machineInfoDocument.SelectSingleNode("/mos/listMachInfo/supportedProfiles/mosProfile[@number='0']") ??
                    machineInfoDocument.SelectSingleNode("/mos/listMachInfo/mosProfile0");
                if (testMode != MosCompatibilityMode.Mos26 && profile == null)
                {
                    Log.Error("PROFILE 0 FALHOU: listMachInfo nao anuncia Profile 0 no formato esperado.");
                    return false;
                }
                if (profile != null)
                {
                    string profileValue = profile.InnerText.Trim().ToUpperInvariant();
                    if (profileValue != "YES" && profileValue != "TRUE" && profileValue != "1")
                    {
                        Log.Error("PROFILE 0 FALHOU: anuncio do Profile 0 tem valor nao afirmativo: '" + profile.InnerText.Trim() + "'.");
                        return false;
                    }
                }
                if (IsLegacy28(testMode) &&
                    machineInfoDocument.SelectSingleNode("/mos/listMachInfo/mosProfile0") == null)
                {
                    Log.Error("PROFILE 0 FALHOU: a variante 2.8 legada exige mosProfile0 plano.");
                    return false;
                }
                if ((IsModern28(testMode) || testMode == MosCompatibilityMode.Mos40) &&
                    machineInfoDocument.SelectSingleNode("/mos/listMachInfo/supportedProfiles/mosProfile[@number='0']") == null)
                {
                    Log.Error("PROFILE 0 FALHOU: a variante moderna exige supportedProfiles/mosProfile.");
                    return false;
                }

                string manufacturer = GetNodeText(machineInfoDocument, "/mos/listMachInfo/manufacturer", "nao informado");
                string model = GetNodeText(machineInfoDocument, "/mos/listMachInfo/model", "nao informado");
                string revision = GetNodeText(machineInfoDocument, "/mos/listMachInfo/mosRev", "nao informado");
                if (revision != MosRevision(testMode))
                {
                    Log.Error("PROFILE 0 FALHOU: mosRev esperado='" + MosRevision(testMode) + "', recebido='" + revision + "'.");
                    return false;
                }
                Log.Ok("PROFILE 0 listMachInfo VALIDADO: fabricante='" + manufacturer + "', modelo='" + model + "', MOS rev='" + revision + "'.");
                return true;
            }
            catch (TimeoutException exception)
            {
                Log.Error("MOS PROFILE 0 TIMEOUT em " + endpoint + ": " + exception.Message + " Socket abriu, mas a aplicacao nao respondeu ao XML MOS.");
                return false;
            }
            catch (XmlException exception)
            {
                Log.Error("MOS PROFILE 0 XML INVALIDO em " + endpoint + ": " + exception.Message);
                return false;
            }
            catch (SocketException exception)
            {
                LogSocketFailure("MOS PROFILE 0", endpoint, exception);
                return false;
            }
            catch (Exception exception)
            {
                Log.Error("MOS PROFILE 0 FALHOU em " + endpoint + " | " + exception.GetType().Name + ": " + exception.Message);
                return false;
            }
            finally
            {
                try { client.Close(); } catch { }
            }
        }

        private static int RunCompatibilitySelfTest(Options options)
        {
            Log.Section("AUTOTESTE MOS PROFILE 0");
            List<string> failures = new List<string>();
            MosCompatibilityMode[] modes = new MosCompatibilityMode[]
            {
                MosCompatibilityMode.Mos26,
                MosCompatibilityMode.Mos280,
                MosCompatibilityMode.Mos281,
                MosCompatibilityMode.Mos282,
                MosCompatibilityMode.Mos283,
                MosCompatibilityMode.Mos284,
                MosCompatibilityMode.Mos285,
                MosCompatibilityMode.Mos40
            };

            foreach (MosCompatibilityMode mode in modes)
            {
                try
                {
                    XmlDocument heartbeat = ParseMosXml(BuildHeartbeat(options.MosId, options.NcsId, mode));
                    XmlDocument machineInfo = ParseMosXml(BuildListMachInfo(options.MosId, options.NcsId, options, mode));
                    AssertSelfTest(heartbeat.SelectSingleNode("/mos/heartbeat/time") != null, mode, "heartbeat/time ausente", failures);
                    AssertSelfTest((heartbeat.SelectSingleNode("/mos/messageID") != null) == UsesMessageId(mode), mode, "regra de messageID incorreta", failures);
                    AssertSelfTest(GetNodeText(machineInfo, "/mos/listMachInfo/manufacturer", "") == "TCP_DOCTOR", mode, "manufacturer diferente de TCP_DOCTOR", failures);
                    AssertSelfTest(GetNodeText(machineInfo, "/mos/listMachInfo/mosRev", "") == MosRevision(mode), mode, "mosRev incorreto", failures);

                    if (mode == MosCompatibilityMode.Mos26)
                    {
                        AssertSelfTest(machineInfo.SelectSingleNode("/mos/messageID") == null, mode, "MOS 2.6 nao deve emitir messageID", failures);
                        AssertSelfTest(machineInfo.SelectSingleNode("/mos/listMachInfo/mosProfile0") == null && machineInfo.SelectSingleNode("/mos/listMachInfo/supportedProfiles") == null, mode, "MOS 2.6 nao deve emitir campos de profiles", failures);
                    }
                    else if (IsLegacy28(mode))
                    {
                        AssertSelfTest(GetNodeText(machineInfo, "/mos/listMachInfo/mosProfile0", "") == "YES", mode, "mosProfile0 plano ausente", failures);
                        bool shouldHaveProfile7 = mode == MosCompatibilityMode.Mos282 || mode == MosCompatibilityMode.Mos283;
                        AssertSelfTest((machineInfo.SelectSingleNode("/mos/listMachInfo/mosProfile7") != null) == shouldHaveProfile7, mode, "presenca de mosProfile7 incorreta", failures);
                        AssertSelfTest(machineInfo.SelectSingleNode("/mos/listMachInfo/supportedProfiles") == null, mode, "formato legado nao deve emitir supportedProfiles", failures);
                    }
                    else
                    {
                        XmlNodeList profiles = machineInfo.SelectNodes("/mos/listMachInfo/supportedProfiles/mosProfile");
                        AssertSelfTest(profiles != null && profiles.Count == 8, mode, "supportedProfiles deve conter profiles 0-7", failures);
                        AssertSelfTest(GetNodeText(machineInfo, "/mos/listMachInfo/supportedProfiles/mosProfile[@number='0']", "") == "YES", mode, "Profile 0 moderno ausente", failures);
                    }

                    Encoding wireEncoding = new UnicodeEncoding(true, false, true);
                    string roundTrip = wireEncoding.GetString(wireEncoding.GetBytes(machineInfo.OuterXml));
                    AssertSelfTest(roundTrip == machineInfo.OuterXml, mode, "round-trip UTF-16BE falhou", failures);
                    if (!failures.Any(delegate(string failure) { return failure.StartsWith(MosCompatibilityName(mode) + ":", StringComparison.Ordinal); }))
                    {
                        Log.Ok("Autoteste passou: " + MosCompatibilityName(mode) + ".");
                    }
                }
                catch (Exception exception)
                {
                    failures.Add(MosCompatibilityName(mode) + ": excecao " + exception.GetType().Name + " - " + exception.Message);
                }
            }

            XmlDocument noMessageId = ParseMosXml("<mos><mosID>a</mosID><ncsID>b</ncsID><reqMachInfo/></mos>");
            XmlDocument withMessageId = ParseMosXml("<mos><mosID>a</mosID><ncsID>b</ncsID><messageID>1</messageID><reqMachineInfo/></mos>");
            XmlDocument keepAlive = ParseMosXml("<mos><mosID>a</mosID><ncsID>b</ncsID><keepalive/></mos>");
            AssertSelfTest(ResolveCompatibility(noMessageId, MosCompatibilityMode.Auto) == MosCompatibilityMode.Mos26, MosCompatibilityMode.Auto, "deteccao sem messageID deveria escolher 2.6", failures);
            AssertSelfTest(ResolveCompatibility(withMessageId, MosCompatibilityMode.Auto) == MosCompatibilityMode.Mos285, MosCompatibilityMode.Auto, "deteccao com messageID deveria escolher 2.8.5", failures);
            AssertSelfTest(ResolveCompatibility(keepAlive, MosCompatibilityMode.Auto) == MosCompatibilityMode.Mos40, MosCompatibilityMode.Auto, "keepalive legado deveria escolher 4.0", failures);

            if (failures.Count == 0)
            {
                Log.Ok("AUTOTESTE CONCLUIDO: todas as variantes TCP do MOS Profile 0 passaram.");
                Log.Info("MOS 3.x nao entra neste teste: a especificacao usa HTTP/SOAP Web Services, e o listener informa esse transporte separadamente.");
                return 0;
            }

            foreach (string failure in failures) Log.Error(failure);
            Log.Error("AUTOTESTE FALHOU com " + failures.Count + " erro(s).");
            return 1;
        }

        private static void AssertSelfTest(bool condition, MosCompatibilityMode mode, string message, List<string> failures)
        {
            if (!condition) failures.Add(MosCompatibilityName(mode) + ": " + message);
        }

        private static XmlDocument ParseMosXml(string xml)
        {
            if (xml.IndexOf("<!DOCTYPE", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                throw new XmlException("DOCTYPE nao e aceito pelo diagnostico por seguranca.");
            }
            XmlDocument document = new XmlDocument();
            document.XmlResolver = null;
            document.LoadXml(xml);
            return document;
        }

        private static string GetNodeText(XmlDocument document, string xpath, string fallback)
        {
            XmlNode node = document.SelectSingleNode(xpath);
            if (node == null || String.IsNullOrWhiteSpace(node.InnerText)) return fallback;
            return node.InnerText.Trim();
        }

        private static string BuildKeepAlive(string mosId, string ncsId)
        {
            return BuildMosEnvelope(mosId, ncsId, null, "  <keepAlive />");
        }

        private static string BuildHeartbeat(string mosId, string ncsId)
        {
            return BuildHeartbeat(mosId, ncsId, MosCompatibilityMode.Mos40);
        }

        private static string BuildHeartbeat(string mosId, string ncsId, MosCompatibilityMode mode)
        {
            string body = "  <heartbeat>\r\n" +
                "    <time>" + MosTimeNow() + "</time>\r\n" +
                "  </heartbeat>";
            return BuildMosEnvelope(mosId, ncsId, UsesMessageId(mode) ? NextMessageId() : null, body);
        }

        private static string BuildReqMachInfo(string mosId, string ncsId)
        {
            return BuildReqMachInfo(mosId, ncsId, MosCompatibilityMode.Mos40);
        }

        private static string BuildReqMachInfo(string mosId, string ncsId, MosCompatibilityMode mode)
        {
            return BuildMosEnvelope(mosId, ncsId, UsesMessageId(mode) ? NextMessageId() : null, "  <reqMachInfo />");
        }

        private static string BuildListMachInfo(string mosId, string ncsId, Options options, MosCompatibilityMode mode)
        {
            string machine = EscapeXml(Environment.MachineName);
            StringBuilder body = new StringBuilder();
            body.Append("  <listMachInfo>\r\n");
            body.Append("    <manufacturer>TCP_DOCTOR</manufacturer>\r\n");
            body.Append(
                "    <model>TcpPortDoctor</model>\r\n" +
                "    <hwRev></hwRev>\r\n" +
                "    <swRev>1.2.0</swRev>\r\n" +
                "    <DOM></DOM>\r\n" +
                "    <SN>" + machine + "</SN>\r\n" +
                "    <ID>" + EscapeXml(options.MosId) + "</ID>\r\n" +
                "    <time>" + MosTimeNow() + "</time>\r\n" +
                "    <mosRev>" + MosRevision(mode) + "</mosRev>\r\n");

            if (IsLegacy28(mode))
            {
                int lastProfile = (mode == MosCompatibilityMode.Mos282 || mode == MosCompatibilityMode.Mos283) ? 7 : 6;
                for (int profile = 0; profile <= lastProfile; profile++)
                {
                    body.Append("    <mosProfile").Append(profile).Append(">").Append(profile == 0 ? "YES" : "NO").Append("</mosProfile").Append(profile).Append(">\r\n");
                }
            }
            else if (IsModern28(mode) || mode == MosCompatibilityMode.Mos40)
            {
                body.Append("    <supportedProfiles deviceType=\"").Append(EscapeXml(options.DeviceType)).Append("\">\r\n");
                for (int profile = 0; profile <= 7; profile++)
                {
                    body.Append("      <mosProfile number=\"").Append(profile).Append("\">").Append(profile == 0 ? "YES" : "NO").Append("</mosProfile>\r\n");
                }
                body.Append("    </supportedProfiles>\r\n");
            }

            body.Append("  </listMachInfo>");
            return BuildMosEnvelope(mosId, ncsId, UsesMessageId(mode) ? NextMessageId() : null, body.ToString());
        }

        private static bool UsesMessageId(MosCompatibilityMode mode)
        {
            return mode != MosCompatibilityMode.Mos26 && mode != MosCompatibilityMode.Mos280;
        }

        private static string MosRevision(MosCompatibilityMode mode)
        {
            if (mode == MosCompatibilityMode.Mos26) return "2.6";
            if (mode == MosCompatibilityMode.Mos40) return "4.0";
            if (mode == MosCompatibilityMode.Mos280) return "2.8";
            if (mode == MosCompatibilityMode.Mos281) return "2.8.1";
            if (mode == MosCompatibilityMode.Mos282) return "2.8.2";
            if (mode == MosCompatibilityMode.Mos283) return "2.8.3";
            if (mode == MosCompatibilityMode.Mos284) return "2.8.4";
            return "2.8.5";
        }

        private static MosCompatibilityMode ResolveCompatibility(XmlDocument document, MosCompatibilityMode configured)
        {
            if (configured != MosCompatibilityMode.Auto) return configured;
            if (document.SelectSingleNode("/mos/keepAlive") != null || document.SelectSingleNode("/mos/keepalive") != null)
                return MosCompatibilityMode.Mos40;
            if (document.SelectSingleNode("/mos/messageID") == null)
                return MosCompatibilityMode.Mos26;
            return MosCompatibilityMode.Mos285;
        }

        private static string MosCompatibilityName(MosCompatibilityMode mode)
        {
            if (mode == MosCompatibilityMode.Auto) return "automatico (2.6 sem messageID; 4.0 por keepAlive; demais 2.8 moderno)";
            if (mode == MosCompatibilityMode.Mos26) return "MOS 2.6 socket";
            if (mode == MosCompatibilityMode.Mos280) return "MOS 2.8.0 (perfis planos 0-6, sem messageID)";
            if (mode == MosCompatibilityMode.Mos281) return "MOS 2.8.1 (perfis planos 0-6)";
            if (mode == MosCompatibilityMode.Mos282) return "MOS 2.8.2 (perfis planos 0-7)";
            if (mode == MosCompatibilityMode.Mos283) return "MOS 2.8.3 (perfis planos 0-7)";
            if (mode == MosCompatibilityMode.Mos284) return "MOS 2.8.4 (supportedProfiles)";
            if (mode == MosCompatibilityMode.Mos285) return "MOS 2.8.5 (supportedProfiles)";
            return "MOS 4.0 socket";
        }

        private static bool IsLegacy28(MosCompatibilityMode mode)
        {
            return mode == MosCompatibilityMode.Mos280 || mode == MosCompatibilityMode.Mos281 ||
                mode == MosCompatibilityMode.Mos282 || mode == MosCompatibilityMode.Mos283;
        }

        private static bool IsModern28(MosCompatibilityMode mode)
        {
            return mode == MosCompatibilityMode.Mos284 || mode == MosCompatibilityMode.Mos285;
        }

        private static string BuildMosEnvelope(string mosId, string ncsId, string messageId, string body)
        {
            StringBuilder builder = new StringBuilder();
            builder.Append("<mos>\r\n");
            builder.Append("  <mosID>").Append(EscapeXml(mosId)).Append("</mosID>\r\n");
            builder.Append("  <ncsID>").Append(EscapeXml(ncsId)).Append("</ncsID>\r\n");
            if (!String.IsNullOrEmpty(messageId))
            {
                builder.Append("  <messageID>").Append(EscapeXml(messageId)).Append("</messageID>\r\n");
            }
            builder.Append(body).Append("\r\n");
            builder.Append("</mos>");
            return builder.ToString();
        }

        private static string NextMessageId()
        {
            return Interlocked.Increment(ref messageSequence).ToString(CultureInfo.InvariantCulture);
        }

        private static string MosTimeNow()
        {
            return DateTime.Now.ToString("yyyy-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture);
        }

        private static string EscapeXml(string value)
        {
            return System.Security.SecurityElement.Escape(value ?? "") ?? "";
        }

        private static void SendMosXml(NetworkStream stream, string xml, Encoding encoding, string messageType, string endpoint)
        {
            byte[] bytes = encoding.GetBytes(xml);
            Log.Section("MOS ENVIADO PARA " + endpoint + " - " + messageType);
            Log.Info("Codificacao: " + (encoding.CodePage == 1201 ? "UTF-16 big-endian (UCS-2 MOS)" : encoding.EncodingName) + "; bytes=" + bytes.Length);
            LogXml(xml);
            stream.Write(bytes, 0, bytes.Length);
            stream.Flush();
        }

        private static void LogXml(string xml)
        {
            if (xml == null)
            {
                Log.Raw("<XML nulo>");
                return;
            }
            foreach (string line in xml.Split(new string[] { "\r\n", "\n" }, StringSplitOptions.None))
            {
                Log.Raw(line);
            }
        }

        private static int RunConnectTest(Options options)
        {
            Log.Section("TESTE DE CONEXAO");
            IPAddress[] addresses;
            try
            {
                addresses = Dns.GetHostAddresses(options.Target);
                if (addresses.Length == 0)
                {
                    Log.Error("O alvo nao resolveu nenhum endereco: " + options.Target);
                    return 1;
                }
                foreach (IPAddress address in addresses)
                {
                    Log.Info("DNS: " + options.Target + " -> " + address + " (" + address.AddressFamily + ")");
                }
            }
            catch (SocketException exception)
            {
                LogSocketFailure("DNS", options.Target, exception);
                return 1;
            }

            int failures = 0;
            foreach (int port in options.Ports)
            {
                if (!TryConnect(options.Target, port, options.TimeoutMilliseconds, "CONEXAO"))
                {
                    failures++;
                }
            }

            if (failures == 0)
            {
                Log.Ok("Todas as portas aceitaram conexao TCP no alvo " + options.Target + ".");
                return 0;
            }

            Log.Error(failures + " de " + options.Ports.Length + " porta(s) falharam no alvo " + options.Target + ".");
            Log.Info("Timeout costuma indicar descarte por firewall/rota; ConnectionRefused costuma indicar host alcancavel sem listener naquela porta.");
            return 1;
        }

        private static bool TryConnect(string host, int port, int timeoutMilliseconds, string label)
        {
            TcpClient client = new TcpClient();
            Stopwatch stopwatch = Stopwatch.StartNew();
            try
            {
                IAsyncResult result = client.BeginConnect(host, port, null, null);
                bool completed = result.AsyncWaitHandle.WaitOne(timeoutMilliseconds, false);
                if (!completed)
                {
                    Log.Error(label + " FALHOU: " + host + ":" + port + " | TIMEOUT apos " + timeoutMilliseconds + " ms. Possiveis causas: firewall descartando, rota, NAT ou host desligado.");
                    return false;
                }

                client.EndConnect(result);
                stopwatch.Stop();
                Log.Ok(label + " OK: " + client.Client.LocalEndPoint + " -> " + client.Client.RemoteEndPoint + " | " + stopwatch.ElapsedMilliseconds + " ms");
                return true;
            }
            catch (SocketException exception)
            {
                stopwatch.Stop();
                LogSocketFailure(label, host + ":" + port + " apos " + stopwatch.ElapsedMilliseconds + " ms", exception);
                return false;
            }
            catch (Exception exception)
            {
                stopwatch.Stop();
                Log.Error(label + " FALHOU: " + host + ":" + port + " | " + exception.GetType().Name + ": " + exception.Message);
                return false;
            }
            finally
            {
                client.Close();
            }
        }

        private static IPAddress ResolveAddress(string hostOrAddress, bool preferIPv4)
        {
            IPAddress parsed;
            if (IPAddress.TryParse(hostOrAddress, out parsed))
            {
                return parsed;
            }

            IPAddress[] addresses = Dns.GetHostAddresses(hostOrAddress);
            if (preferIPv4)
            {
                foreach (IPAddress address in addresses)
                {
                    if (address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        return address;
                    }
                }
            }
            if (addresses.Length > 0)
            {
                return addresses[0];
            }
            throw new InvalidOperationException("Nenhum endereco encontrado.");
        }

        private static bool IsLocalAddress(IPAddress address)
        {
            if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) || IPAddress.IsLoopback(address))
            {
                return true;
            }

            try
            {
                foreach (NetworkInterface networkInterface in NetworkInterface.GetAllNetworkInterfaces())
                {
                    foreach (UnicastIPAddressInformation local in networkInterface.GetIPProperties().UnicastAddresses)
                    {
                        if (local.Address.Equals(address))
                        {
                            return true;
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                Log.Warn("Nao foi possivel confirmar todos os IPs locais: " + exception.Message);
            }
            return false;
        }

        private static IPAddress GetSelfTestAddress(IPAddress bindAddress)
        {
            if (bindAddress.Equals(IPAddress.Any))
            {
                return IPAddress.Loopback;
            }
            if (bindAddress.Equals(IPAddress.IPv6Any))
            {
                return IPAddress.IPv6Loopback;
            }
            return bindAddress;
        }

        private static void LogSocketFailure(string operation, string endpoint, SocketException exception)
        {
            string hint = GetSocketHint(exception.SocketErrorCode, exception.ErrorCode);
            Log.Error(operation + " FALHOU: " + endpoint + " | SocketError=" + exception.SocketErrorCode + " | Codigo=" + exception.ErrorCode + " | " + exception.Message);
            if (!String.IsNullOrEmpty(hint))
            {
                Log.Info("Diagnostico provavel: " + hint);
            }
        }

        private static string GetSocketHint(SocketError socketError, int nativeError)
        {
            if (socketError == SocketError.AddressAlreadyInUse || nativeError == 10048)
            {
                return "A porta/endereco ja esta em uso. Veja o PID exibido pelo netstat no inicio do log.";
            }
            if (socketError == SocketError.AddressNotAvailable || nativeError == 10049)
            {
                return "O IP nao pertence a esta maquina, a interface esta desativada ou o endereco foi digitado incorretamente.";
            }
            if (socketError == SocketError.AccessDenied || nativeError == 10013)
            {
                return "Acesso negado. Verifique faixas de portas excluidas/reservadas, politica de seguranca, antivirus/EDR e tente executar como Administrador apenas para comparar.";
            }
            if (socketError == SocketError.ConnectionRefused || nativeError == 10061)
            {
                return "O host respondeu, mas nao ha servico escutando nessa porta (ou um firewall rejeitou ativamente).";
            }
            if (socketError == SocketError.TimedOut || nativeError == 10060)
            {
                return "Nao houve resposta. Possiveis causas: firewall descartando pacotes, rota/NAT/VLAN, IP errado ou host desligado.";
            }
            if (socketError == SocketError.HostNotFound || nativeError == 11001)
            {
                return "O nome nao foi resolvido pelo DNS. Teste com o IP e confira DNS/sufixo de dominio.";
            }
            if (socketError == SocketError.NetworkUnreachable || socketError == SocketError.HostUnreachable)
            {
                return "Nao existe rota funcional ate o destino. Confira gateway, mascara, VPN e segmentacao de rede.";
            }
            return "Consulte o codigo SocketError e compare com o estado das interfaces, netstat, firewall e portas excluidas registrados acima.";
        }

        private static void PrintFirewallGuidance(int[] ports)
        {
            string portList = String.Join(",", ports.Select(delegate(int port) { return port.ToString(); }).ToArray());
            Log.Section("PROXIMO TESTE RECOMENDADO");
            Log.Info("Enquanto este programa estiver em --listen, rode em OUTRA maquina:");
            Log.Raw("TcpPortDoctor.exe --connect <IP-DESTA-MAQUINA> --ports " + portList);
            Log.Info("Se o bind local passa mas a conexao externa falha, investigue primeiro o Firewall do Windows e a rede.");
            Log.Info("Comando sugerido para um administrador CRIAR uma regra (este programa nao o executa):");
            Log.Raw("netsh advfirewall firewall add rule name=\"TcpPortDoctor " + portList + "\" dir=in action=allow protocol=TCP localport=" + portList);
            Log.Warn("Remova a regra de teste depois, caso nao deva permanecer no ambiente.");
        }

        private static void RunAndLogCommand(string executable, string arguments, int timeoutMilliseconds)
        {
            Log.Info("Comando: " + executable + " " + arguments);
            string output = CaptureCommand(executable, arguments, timeoutMilliseconds);
            if (String.IsNullOrWhiteSpace(output))
            {
                Log.Warn("O comando nao retornou texto ou nao estava disponivel.");
                return;
            }
            foreach (string line in output.Split(new string[] { "\r\n", "\n" }, StringSplitOptions.None))
            {
                if (!String.IsNullOrWhiteSpace(line))
                {
                    Log.Raw(line);
                }
            }
        }

        private static string CaptureCommand(string executable, string arguments, int timeoutMilliseconds)
        {
            try
            {
                ProcessStartInfo startInfo = new ProcessStartInfo();
                startInfo.FileName = executable;
                startInfo.Arguments = arguments;
                startInfo.UseShellExecute = false;
                startInfo.CreateNoWindow = true;
                startInfo.RedirectStandardOutput = true;
                startInfo.RedirectStandardError = true;

                using (Process process = new Process())
                {
                    StringBuilder output = new StringBuilder();
                    process.StartInfo = startInfo;
                    process.OutputDataReceived += delegate(object sender, DataReceivedEventArgs eventArgs)
                    {
                        if (eventArgs.Data != null)
                        {
                            lock (output) { output.AppendLine(eventArgs.Data); }
                        }
                    };
                    process.ErrorDataReceived += delegate(object sender, DataReceivedEventArgs eventArgs)
                    {
                        if (eventArgs.Data != null)
                        {
                            lock (output) { output.AppendLine("STDERR: " + eventArgs.Data); }
                        }
                    };
                    process.Start();
                    process.BeginOutputReadLine();
                    process.BeginErrorReadLine();
                    if (!process.WaitForExit(timeoutMilliseconds))
                    {
                        try { process.Kill(); } catch { }
                        lock (output) { output.AppendLine("TIMEOUT: comando excedeu " + timeoutMilliseconds + " ms."); }
                    }
                    else
                    {
                        process.WaitForExit();
                        if (process.ExitCode != 0)
                        {
                            lock (output) { output.AppendLine("Codigo de saida: " + process.ExitCode); }
                        }
                    }
                    lock (output) { return output.ToString(); }
                }
            }
            catch (Exception exception)
            {
                return "Falha ao executar comando: " + exception.GetType().Name + ": " + exception.Message;
            }
        }
    }
}
