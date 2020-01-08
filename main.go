package main

import (
	"bufio"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"leon.wtf/encryption/rsa"
)

func main() {

	// TEMP
	//os.Exit(0)
	// END TEMP

	fmt.Print("OPTIONS:\n  (1) Connect to another user\n  (2) Listen for incoming connections\n  (3) Manage RSA keys\n> ")
	choice1, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		log.Fatal(err)
	}

	switch choice1 {
	case "1\n":
		fmt.Print("Please enter the IP address you want to connect to (IP:port)\n> ")
		ipport, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			log.Fatal(err)
		}
		ipport = strings.Trim(ipport, "\n")
		conn, err := connect(ipport)
		if err != nil {
			log.Fatal(err)
		}
		defer (*conn).Close()
		startConversation(conn)
	case "2\n":
		conn, err := waitForConnection(2015)
		if err != nil {
			log.Fatal(err)
		}
		defer (*conn).Close()
		startConversation(conn)
	case "3\n":
		fmt.Print("OPTIONS:\n  (1) Check key files\n  (2) Generate RSA keys\n  (3) Send RSA public key\n  (4) Receive RSA public key\n> ")
		choice2, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			log.Fatal(err)
		}
		switch choice2 {
		case "1\n":
			ownPrivKey, ownPubKey, foreignPubKey := checkKeyFiles()
			fmt.Println("  Own private key:    ", ownPrivKey)
			fmt.Println("  Own public key:     ", ownPubKey)
			fmt.Println("  Partners public key:", foreignPubKey)
			if ownPrivKey && ownPubKey && foreignPubKey {
				fmt.Println("  --> All keys have been found")
			}
		case "2\n":
			fmt.Println("Generating new key pair...")
			kp, err := rsa.NewKeyPair(rsa.RandomPrime(10), rsa.RandomPrime(10))
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println("Saving key pair:", kp)
			rsa.SaveKeyPair(kp)
			fmt.Println("Keys successfully saved")
		case "3\n":
			fmt.Print("Please enter the IP address you want to send your key to (IP:port)\n> ")
			ipport, err := bufio.NewReader(os.Stdin).ReadString('\n')
			if err != nil {
				log.Fatal(err)
			}
			ipport = strings.Trim(ipport, "\n")
			conn, err := connect(ipport)
			if err != nil {
				log.Fatal(err)
			}
			defer (*conn).Close()
			err = rsa.SendPublicKey(conn)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println("Key sent")
		case "4\n":
			conn, err := waitForConnection(2015)
			if err != nil {
				log.Fatal(err)
			}
			defer (*conn).Close()
			err = rsa.ReceivePublicKey(conn)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println("Public key received")
		default:
			log.Fatal("Please only use 1, 2, 3 or 4 as option")
		}
	default:
		log.Fatal("Please only use 1, 2 or 3 as option")
	}

}

func startConversation(conn *net.Conn) {

	// load keys
	ownKeys, err := rsa.LoadOwnKeyPair()
	if err != nil {
		log.Fatal(err)
	}
	partnerPubKey, err := rsa.LoadPartnerPubKey()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("RSA keys successfully loaded")

	// start receiver routine
	go receive(conn, &ownKeys.Priv)

	// send
	for {
		fmt.Print("> ")
		userIn, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if userIn == "exit\n" {
			break
		}
		userInEnc := partnerPubKey.Encrypt(strings.Trim(userIn, "\n"))
		//fmt.Println("Encrypted user in:", userInEnc) //
		fmt.Println("SEND >", strings.Trim(userIn, "\n"))

		(*conn).Write([]byte(userInEnc))
	}

}

func connect(ipport string) (*net.Conn, error) {

	fmt.Println("Connecting to", ipport, "...")

	// create connection
	conn, err := net.Dial("tcp", ipport)
	if err != nil {
		return nil, err
	}

	fmt.Println("Connection successfull")

	return &conn, nil

}

func waitForConnection(listenPort int) (*net.Conn, error) {

	ip, err := getLocalIP()
	if err != nil {
		addr := net.IPv4(0, 0, 0, 0)
		ip = &addr
	}
	fmt.Println("Listening on", (*ip).String()+":"+strconv.Itoa(listenPort), "...")

	ln, err := net.Listen("tcp", ":"+strconv.Itoa(listenPort))
	if err != nil {
		return nil, err
	}
	defer ln.Close()

	var conn net.Conn
	for {
		conn, err = ln.Accept()
		if err != nil {
			return nil, err
		}
		if conn != nil {
			break
		}
	}

	fmt.Println("New connection from", conn.RemoteAddr().String())

	return &conn, nil

}

func receive(conn *net.Conn, key *rsa.PrivateKey) {

	for {
		rcvd, err := bufio.NewReader(*conn).ReadString('\n')
		if err != nil {
			log.Fatal(err)
		}
		rcvdDec := (*key).Decrypt(strings.ReplaceAll(rcvd, "\n", ""))
		fmt.Println("\nRCVD >", rcvdDec)
		fmt.Print("> ")
	}

}

func checkKeyFiles() (bool, bool, bool) { // TODO check for integrity

	ownPrivKey, ownPubKey, foreignPubKey := false, false, false

	files, err := ioutil.ReadDir("./")
	if err != nil {
		log.Fatal("Error checking key files")
	}
	for _, file := range files {
		switch file.Name() {
		case "ownpriv.key":
			ownPrivKey = true
		case "ownpub.key":
			ownPubKey = true
		case "partnerpub.key":
			foreignPubKey = true
		}
	}
	return ownPrivKey, ownPubKey, foreignPubKey
}

func getLocalIP() (*net.IP, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return &ipnet.IP, nil
			}
		}
	}
	return nil, errors.New("Error getting own local IP")
}
