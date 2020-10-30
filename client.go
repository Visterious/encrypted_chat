package main

import (
	"os"
	"fmt"
	"net"
	"bufio"
	"strings"
	"time"
	"crypto/rsa"
	"./crypt"
)

const (
	// bytes to determine the end of the message
	END_BYTES = "\000\001\002\003\004\005"
	ADDR_SERVER = ":8080" // server address [IP]:PORT
)

var (
	username string	
	// user's private and public RSA keys
	priv, pub = crypt.GenerateKeys(2048)
	// user's session key
	session_key []byte = make([]byte, 256)
)

func main() {
	// try to connect to server
	conn, err := net.Dial("tcp", ADDR_SERVER)
	if err != nil {
		panic("can't connect to server!")
	}
	defer conn.Close()

	username = inputString("Nickname: ")

	keyExchange(conn)
	go ClientOutput(conn)
	ClientInput(conn)
	
}

func keyExchange(conn net.Conn) {
	var (
		encoded_chat_pub []byte = make([]byte, 5000)
		chat_AES_key_enc []byte
		chat_AES_key []byte = make([]byte, 256)
		timer = time.NewTimer(2*time.Second)
		chat_pub *rsa.PublicKey
	)
	// timer for key exchange
	go func() {
		<- timer.C
		fmt.Println("Connection failure")
		os.Exit(1)
	}()

	// sending the user's public key to server
	conn.Write(crypt.EncodePublic(pub))
	// receiving the server's public key
	conn.Read(encoded_chat_pub)
	chat_pub = crypt.DecodePublic(string(encoded_chat_pub))

	// generation of session key
	key := crypt.SessionKey(32)
	// encrypting session key with server public key
	chat_AES_key_enc, err := crypt.EncryptRSA(key, chat_pub)
	if err != nil {
		panic(err)
	}

	// sending encrypted session key to server
	conn.Write(chat_AES_key_enc)
	// receiving encrypted session key
	conn.Read(chat_AES_key)
	// decrypting encrypted session key
	session_key, err = crypt.DecryptRSA(chat_AES_key, priv)
	if err != nil {
		panic(err)
	}

	timer.Stop()
	fmt.Println("Connection success")
}

func ClientInput(conn net.Conn) {
	var (
		template []byte
	)
	for {
		// message input
		var message = inputString("")
		if len(message) != 0 {
			// message formating
			template = []byte(
				fmt.Sprintf("[%s]: %s", username, message),
			)
			// message encryption
			message = crypt.Encrypt(session_key, string(template)) + END_BYTES
			// sending message to server
			conn.Write([]byte(message))
		}
	}
}

func ClientOutput(conn net.Conn) {
	var (
		buffer = make([]byte, 512)
		message string
	)
	close: for {
		message = ""
		for {
			// receiving message
			length, err := conn.Read(buffer)
			if err != nil { break close }
			message += string(buffer[:length])
			if strings.HasSuffix(message, END_BYTES) {
				// deleting of END_BYTES
				message = strings.TrimSuffix(message, END_BYTES)
				// message decryption
				message = crypt.Decrypt(session_key, message)
				break
			}
		}
		// message output
		fmt.Println(message)
	}
}

func inputString(text string) string {
	fmt.Print(text)
	message, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.Replace(message, "\n", "", -1)
}