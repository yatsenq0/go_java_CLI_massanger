import java.io.*;
import java.net.*;
import java.util.*;
import java.security.MessageDigest;

public class Main {

    private static final int PORT = 8080;
    private static final String CHAT_LOG = "chat.log";
    private static final String TARGET_IP_FILE = "target.ip";

    private static String remoteIp = null;
    private static volatile boolean running = true;
    private static int lastPrintedLineCount = 0;

    public static void main(String[] args) {
        try {
            // Generate simple device ID
            String deviceId = generateDeviceId();
            System.out.println("[Messenger] Started");
            System.out.println("Device ID: " + deviceId);
            System.out.println("Port:      " + PORT);
            System.out.println();

            // Get local IP (best effort)
            String localIp = getLocalIpAddress();
            System.out.println("Local IP:  " + (localIp != null ? localIp : "unknown"));
            System.out.println();

            // Load or ask for remote IP
            if (fileExists(TARGET_IP_FILE)) {
                remoteIp = readFirstLine(TARGET_IP_FILE).trim();
                System.out.println("Messages will be sent to: " + remoteIp);
            } else {
                System.out.println("To chat over the Internet:");
                System.out.println("  - Run messenger.bat on a Windows PC");
                System.out.println("  - Find its PUBLIC IP (e.g., https://api.ipify.org )");
                System.out.println("  - Forward port " + PORT + " on its router");
                System.out.println();
                System.out.print("Enter PUBLIC IP of the other PC: ");
                remoteIp = new Scanner(System.in).nextLine().trim();
                if (remoteIp.isEmpty()) {
                    System.out.println("No IP provided. Exiting.");
                    return;
                }
                writeStringToFile(TARGET_IP_FILE, remoteIp);
            }

            System.out.println();
            System.out.println("Ready. Type message and press Enter.");
            System.out.println("Commands: /exit (quit), /ip (change IP)");
            System.out.println("--------------------------------------------------");

            // Start server in background thread
            Thread serverThread = new Thread(new Runnable() {
                public void run() {
                    startServer();
                }
            });
            serverThread.setDaemon(true);
            serverThread.start();

            // Main input loop
            Scanner scanner = new Scanner(System.in);
            while (running) {
                System.out.print("> ");
                String input = scanner.nextLine();

                if ("/exit".equalsIgnoreCase(input.trim())) {
                    break;
                } else if ("/ip".equalsIgnoreCase(input.trim())) {
                    System.out.print("New target IP: ");
                    String newIp = scanner.nextLine().trim();
                    if (!newIp.isEmpty()) {
                        remoteIp = newIp;
                        writeStringToFile(TARGET_IP_FILE, remoteIp);
                        System.out.println("Target IP updated to: " + remoteIp);
                    }
                } else if (!input.trim().isEmpty()) {
                    // Log and send
                    String logLine = "[OUT] " + new Date() + ": " + input;
                    appendToFile(CHAT_LOG, logLine);
                    System.out.println(logLine.substring(6)); // echo without [OUT]

                    sendMessage(remoteIp, input);
                }

                // Print new incoming messages
                printNewMessages();
            }

            running = false;
            System.out.println("\nShutting down...");
            System.exit(0);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void startServer() {
        try {
            ServerSocket serverSocket = new ServerSocket(PORT);
            while (running) {
                try {
                    Socket clientSocket = serverSocket.accept();
                    BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                    String message = in.readLine();
                    if (message != null) {
                        String logLine = "[IN]  " + new Date() + ": " + message;
                        appendToFile(CHAT_LOG, logLine);
                    }
                    clientSocket.close();
                } catch (IOException e) {
                    if (running) {
                        // ignore or log
                    }
                }
            }
            serverSocket.close();
        } catch (IOException e) {
            if (running) {
                System.err.println("Failed to start server on port " + PORT);
            }
        }
    }

    private static void sendMessage(final String ip, final String message) {
        Thread t = new Thread(new Runnable() {
            public void run() {
                try {
                    Socket socket = new Socket(ip, PORT);
                    PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                    out.println(message);
                    socket.close();
                } catch (IOException e) {
                    System.err.println("Send failed to " + ip);
                }
            }
        });
        t.start();
    }

    private static void printNewMessages() {
        try {
            if (!fileExists(CHAT_LOG)) return;

            String[] lines = readAllLines(CHAT_LOG);
            if (lines.length > lastPrintedLineCount) {
                for (int i = lastPrintedLineCount; i < lines.length; i++) {
                    String line = lines[i];
                    if (!line.startsWith("[OUT] ")) {
                        System.out.println(line);
                    }
                }
                lastPrintedLineCount = lines.length;
            }
        } catch (Exception e) {
            // ignore
        }
    }

    // --- Utility methods (Java 6/7 compatible) ---

    private static boolean fileExists(String filename) {
        File f = new File(filename);
        return f.exists();
    }

    private static String readFirstLine(String filename) {
        try {
            BufferedReader br = new BufferedReader(new FileReader(filename));
            String line = br.readLine();
            br.close();
            return line != null ? line : "";
        } catch (IOException e) {
            return "";
        }
    }

    private static String[] readAllLines(String filename) {
        try {
            BufferedReader br = new BufferedReader(new FileReader(filename));
            List<String> list = new ArrayList<String>();
            String line;
            while ((line = br.readLine()) != null) {
                list.add(line);
            }
            br.close();
            return list.toArray(new String[0]);
        } catch (IOException e) {
            return new String[0];
        }
    }

    private static void writeStringToFile(String filename, String content) {
        try {
            PrintWriter pw = new PrintWriter(new FileWriter(filename));
            pw.print(content);
            pw.close();
        } catch (IOException e) {
            // ignore
        }
    }

    private static void appendToFile(String filename, String line) {
        try {
            PrintWriter out = new PrintWriter(new FileWriter(filename, true));
            out.println(line);
            out.close();
        } catch (IOException e) {
            // ignore
        }
    }

    private static String generateDeviceId() {
        try {
            String seed = java.net.InetAddress.getLocalHost().getHostName() + System.getProperty("user.name");
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(seed.getBytes());
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 4; i++) {
                sb.append(String.format("%02x", hash[i] & 0xff));
            }
            return sb.toString();
        } catch (Exception e) {
            return "dev" + Math.abs(new Random().nextInt() % 10000);
        }
    }

    private static String getLocalIpAddress() {
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface iface = interfaces.nextElement();
                if (iface.isLoopback() || !iface.isUp()) continue;
                Enumeration<InetAddress> addresses = iface.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress addr = addresses.nextElement();
                    if (addr instanceof Inet4Address && !addr.isLoopbackAddress()) {
                        return addr.getHostAddress();
                    }
                }
            }
        } catch (Exception e) {
            // ignore
        }
        return null;
    }
}
