package main

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	PORT        = "8080"
	CHAT_LOG    = "chat.log"
	TARGET_IP   = "target.ip"
)

var (
	remoteIP      string
	mu            sync.Mutex
	lastPrinted   int
	running       = true
)

func main() {
	// Generate device ID
	deviceID := generateDeviceID()
	fmt.Println("[Messenger] Started")
	fmt.Println("Device ID:", deviceID)
	fmt.Println("Port:     ", PORT)
	fmt.Println()

	// Get local IP (best effort)
	localIP := getLocalIP()
	fmt.Println("Local IP: ", localIP)
	fmt.Println()

	// Load or ask for remote IP
	if ip, err := readFirstLine(TARGET_IP); err == nil && ip != "" {
		remoteIP = ip
		fmt.Println("Messages will be sent to:", remoteIP)
	} else {
		fmt.Println("To chat over the Internet:")
		fmt.Println("  - Run Main.java or messenger.bat on another device")
		fmt.Println("  - Find its PUBLIC IP (e.g., https://api.ipify.org )")
		fmt.Println("  - Forward port", PORT, "on its router")
		fmt.Println()
		fmt.Print("Enter PUBLIC IP of the other device: ")
		fmt.Scanln(&remoteIP)
		if remoteIP == "" {
			fmt.Println("No IP provided. Exiting.")
			return
		}
		writeFile(TARGET_IP, remoteIP)
	}

	fmt.Println()
	fmt.Println("Ready. Type message and press Enter.")
	fmt.Println("Commands: /exit (quit), /ip (change IP)")
	fmt.Println("--------------------------------------------------")

	// Start server in goroutine
	go startServer()

	// Start log watcher
	go watchLog()

	// Main input loop
	scanner := bufio.NewScanner(os.Stdin)
	for running && scanner.Scan() {
		input := strings.TrimSpace(scanner.Text())

		if input == "/exit" {
			break
		} else if input == "/ip" {
			fmt.Print("New target IP: ")
			var newIP string
			fmt.Scanln(&newIP)
			if newIP != "" {
				remoteIP = newIP
				writeFile(TARGET_IP, remoteIP)
				fmt.Println("Target IP updated to:", remoteIP)
			}
		} else if input != "" {
			// Log outgoing
			logLine := "[OUT] " + time.Now().String() + ": " + input
			appendFile(CHAT_LOG, logLine)
			fmt.Println(logLine[6:]) // echo without [OUT]

			// Send message
			go sendMessage(remoteIP, input)
		}
	}

	running = false
	fmt.Println("\nShutting down...")
	time.Sleep(500 * time.Millisecond)
}

func startServer() {
	listener, err := net.Listen("tcp", ":"+PORT)
	if err != nil {
		if running {
			fmt.Fprintln(os.Stderr, "Failed to start server on port", PORT)
		}
		return
	}
	defer listener.Close()

	for running {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	message, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return
	}
	message = strings.TrimRight(message, "\r\n")
	if message != "" {
		logLine := "[IN]  " + time.Now().String() + ": " + message
		appendFile(CHAT_LOG, logLine)
	}
}

func sendMessage(ip, message string) {
	conn, err := net.Dial("tcp", ip+":"+PORT)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Send failed to", ip)
		return
	}
	defer conn.Close()
	fmt.Fprintln(conn, message)
}

func watchLog() {
	for running {
		lines := readAllLines(CHAT_LOG)
		mu.Lock()
		if len(lines) > lastPrinted {
			for i := lastPrinted; i < len(lines); i++ {
				line := lines[i]
				if !strings.HasPrefix(line, "[OUT] ") {
					fmt.Println(line)
				}
			}
			lastPrinted = len(lines)
		}
		mu.Unlock()
		time.Sleep(2 * time.Second)
	}
}

// --- Helpers ---

func generateDeviceID() string {
	hostname, _ := os.Hostname()
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("USERNAME")
	}
	seed := hostname + user
	hash := sha256.Sum256([]byte(seed))
	return fmt.Sprintf("%x", hash[:4])
}

func getLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "unknown"
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

func readFirstLine(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		return strings.TrimSpace(scanner.Text()), nil
	}
	return "", fmt.Errorf("empty file")
}

func readAllLines(filename string) []string {
	file, err := os.Open(filename)
	if err != nil {
		return []string{}
	}
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines
}

func writeFile(filename, content string) {
	os.WriteFile(filename, []byte(content+"\n"), 0644)
}

func appendFile(filename, line string) {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	defer file.Close()
	file.WriteString(line + "\n")
}
