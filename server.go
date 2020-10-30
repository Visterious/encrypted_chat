package main

import (
	"net"
	"log"
	"time"
	"strings"
	"crypto/rsa"
	"./crypt"
)

const (
	// bytes to determine the end of the message
	END_BYTES = "\000\001\002\003\004\005"
	PORT = ":8080" // Server port
	QUAN = 2 // number of users
)

var (
	Connections = make(map[net.Conn]bool) // active connections
	// user's public RSA keys
	Users = make(map[net.Conn]*rsa.PublicKey)
	Session_key []byte = nil // active session key
	// server private and public RSA keys
	priv, pub = crypt.GenerateKeys(2048)
)

func main() {
	// Listen connections
	listen, err := net.Listen("tcp", PORT)
	if err != nil {
		panic("server error!")
	}
	defer listen.Close()

	for {
		if len(Connections) < QUAN {
			// accepting connections
			conn, err := listen.Accept()
			if err != nil { break }
			keyExchange(conn)
			go handleConnect(conn)
		} else if len(Connections) == 0 {
			// key reset
			Session_key = nil
		}
		time.Sleep(500*time.Millisecond)
	}
}

func keyExchange(conn net.Conn) {
	var ( 
		loc_pub *rsa.PublicKey
		user_pub []byte = make([]byte, 1000)
		chat_AES_key_enc []byte = make([]byte, 256)
		chat_AES_key []byte
	)
	// receiving user's public key
	conn.Read(user_pub)
	loc_pub = crypt.DecodePublic(string(user_pub))
	Users[conn] = loc_pub
	// sending server public key
	conn.Write(crypt.EncodePublic(pub))
	// receiving user's encrypted session key
	conn.Read(chat_AES_key_enc)
	var err error
	// changing the session key if it wasn't there before
	if Session_key == nil {
		Session_key = make([]byte, 128)
		// decrypting session key with server private key
		Session_key, err = crypt.DecryptRSA(chat_AES_key_enc, priv)
		if err != nil {
			panic(err)
		}
	}
	// encrypting session key with user's public key
	chat_AES_key, err = crypt.EncryptRSA(Session_key, Users[conn])
	if err != nil {
		panic(err)
	}
	// sending encrypted session key to user
	conn.Write(chat_AES_key)
}

func handleConnect(conn net.Conn) {
	Connections[conn] = true // add connection to Connections
	var (
		buffer = make([]byte, 512)
		message string
	)
	close: for {
		message = ""
		for {
			// receiving user encrypted messages
			length, err := conn.Read(buffer)
			if err != nil { break close }
			message += string(buffer[:length])
			if strings.HasSuffix(message, END_BYTES) {
				// deleting of END_BYTES
				message = strings.TrimSuffix(message, END_BYTES)
				break
			}
		}
		// server info output
		log.Println(" -> ", message)
		// sending the message to all users except the sender
		for c := range Connections {
			if c == conn { continue }
			c.Write([]byte(message + END_BYTES))
		}
	}
	delete(Connections, conn) // deleting connection
}