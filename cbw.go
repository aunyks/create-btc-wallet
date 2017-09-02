package main

import (
  "fmt"
  "os"
  "bufio"
  "encoding/json"
  "github.com/urfave/cli"
  "math/big"
  "hash"
  "crypto/elliptic"
  "crypto/ecdsa"
  "crypto/rand"
  "crypto/sha256"
  "golang.org/x/crypto/ripemd160"
  "github.com/btcsuite/btcutil/base58"
)

type JSONWallet struct {
  PrivateKey string
  //Address string
}

// TO BE REFACTORED:
// Although this function *happens* to generate a valid
// Bitcoin private key, the associated public key does 
// not satisfy that of a point on the secp256k1 curve.
// 
// This is why we are ignoring the public key / address
// until I finish developing a purely Go secp256k1 library
func createKeyPair() (big.Int, big.Int, big.Int){
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
  return *(privateKey.D), *(privateKey.PublicKey.X), *(privateKey.PublicKey.Y)
}

// Hash a given set of bytes.
// The only two hash functions relevant to this project
// are sha256 and ripemd160.
//
// So, the calling process can specify with which
// function to hash the bytes
func hashBytes(bytes []byte, hashType string) []byte {
  var hashFunc hash.Hash
  if(hashType == "sha"){
    hashFunc = sha256.New()
  } else {
    hashFunc = ripemd160.New()
  }
  hashFunc.Write(bytes)
  return hashFunc.Sum(nil)
}

// TO BE REFACTORED:
// This function's original use was to generate a 
// Bitcoin address that corresponds with a previously
// generated private key. Due to Go's lack of a pure Go
// secp256k1 curve library, however, addresses generated
// did not match with private keys.
//
// While I develop a secp256k1 elliptic curve library in Go,
// This function is to be ignored in current versions of cbw.
func createAddress(curveX big.Int, curveY big.Int) string {
  sixtyFiveByte := append(append([]byte{0x04}, curveX.Bytes()...), curveY.Bytes()...)
  shaHashed := hashBytes(sixtyFiveByte, "sha")
  addedVersionByte := append([]byte{0x00}, hashBytes(shaHashed, "ripemd")...)
  firstLateSha := hashBytes(addedVersionByte, "sha")
  secondLateSha := hashBytes(firstLateSha, "sha")
  checkSumBytes := secondLateSha[0:4]
  addressBytes := append(addedVersionByte, checkSumBytes...)
  return base58.Encode(addressBytes)
}

// Generate a new Wallet Import Format (WIF)-compatible
// private key
func wifPrivateKey(privKey big.Int) string {
  addedVersionByte := append([]byte{0x80}, privKey.Bytes()...)
  firstHash := hashBytes(addedVersionByte, "sha")
  secondHash := hashBytes(firstHash, "sha")
  checkSumBytes := secondHash[0:4]
  keyToEncode := append(addedVersionByte, checkSumBytes...)
  return base58.Encode(keyToEncode)
}

// Just a locally used utility function
func println(msg string) {
  fmt.Println(msg)
}

// Just a locally used utility function
func print(msg string) {
  fmt.Print(msg)
}

// Ask the user a question via stdout
// and read the response via stdin
func prompt(inquiry string) string {
  reader := bufio.NewReader(os.Stdin)
  print(inquiry + " ");
  text, _ := reader.ReadString('\n')
  return text[0 : len(text) - 1]
}

// Something went wrong! Let the user know
// and exit immediately
func panic(mayday string) {
  println(mayday)
  os.Exit(0)
}

// Prompt the user with two options. Then let the calling
// process know which response was given via a boolean
// value (true is for the a value, false for the b value).
//
// If neither are provided. We panic before any more processing
// is handled
func promptABTest(inquiry string, a string, b string) bool {
  response := prompt(inquiry)
  if(response == a){
    return true
  } else if (response == b) {
    return false
  } else {
    panic("Don't understand what you said. Bye!")
  }
  return false
}

func main() {
  file := false
  terminal := false
  app := cli.NewApp()
  app.Name = "cbw"
  app.Version = "0.0.1"
  app.Usage = "Create a new Bitcoin wallet instantly."
  app.Action = func(c *cli.Context) error {
    // Greet upon run
    println("Hello!")
    // Ask how to save the wallet data after creation
    storeFileOrCli := promptABTest(
      "Would you like to store your key data in a file or print to the terminal? (f or t)",
      "f",
      "t",
    )
    // Assess the response
    if(storeFileOrCli) {
      println("Chose to store wallet data to a file.")
      file = true
    } else {
      println("Chose to print wallet data to the terminal.")
      terminal = true
    }
    println("Awesome! Creating Bitcoin wallet...\n")
    // Now create the wallet
    //priv, pubX, pubY := createKeyPair()
    priv, _,_ := createKeyPair()
    privateKey := wifPrivateKey(priv)
    //address := createAddress(pubX, pubY)
    if(terminal){
      println("Private Key:\n" + privateKey)
      //println("Address:\n" + address)
      println("")
    } else {
      newWallet := JSONWallet{privateKey}//, address}
      // Convert the wallet data to a JSON string
      jsonBytes, _ := json.MarshalIndent(newWallet, "", "\t")
      jsonPayload := string(jsonBytes)
      // Write the JSON payload string to a file.
      // If an error occurs then we panic
      file, err := os.OpenFile("wallet.json", os.O_WRONLY|os.O_CREATE, 0666)
      if err != nil {
          panic("Uh oh! Wallet file can't be created.")
      }
      defer file.Close()
  
      w := bufio.NewWriter(file)
      fmt.Fprint(w, jsonPayload)
  
      w.Flush()
      // Upon success, we let the user know that we're
      // done and where the new file is!
      cwd, err := os.Getwd()
      println("Done! Wallet file location:\n" + cwd + fmt.Sprintf("%c", os.PathSeparator) + "wallet.json")
    }
    return nil
  }

  app.Run(os.Args)
}
