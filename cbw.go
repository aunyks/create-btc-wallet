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
  Address string
}

func createKeyPair() (big.Int, big.Int, big.Int){
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
  return *(privateKey.D), *(privateKey.PublicKey.X), *(privateKey.PublicKey.Y)
}

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

func wifPrivateKey(privKey big.Int) string {
  addedVersionByte := append([]byte{0x80}, privKey.Bytes()...)
  firstHash := hashBytes(addedVersionByte, "sha")
  secondHash := hashBytes(firstHash, "sha")
  checkSumBytes := secondHash[0:4]
  keyToEncode := append(addedVersionByte, checkSumBytes...)
  return base58.Encode(keyToEncode)
}

func println(msg string) {
  fmt.Println(msg)
}

func print(msg string) {
  fmt.Print(msg)
}

func prompt(inquiry string) string {
  reader := bufio.NewReader(os.Stdin)
  print(inquiry + " ");
  text, _ := reader.ReadString('\n')
  return text[0 : len(text) - 1]
}

func panic(mayday string) {
  println(mayday)
  os.Exit(0)
}

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
    priv, pubX, pubY := createKeyPair()
    privateKey := wifPrivateKey(priv)
    address := createAddress(pubX, pubY)
    if(terminal){
      println("Private Key:\n" + privateKey)
      println("Address:\n" + address + "\n")
    } else {
      newWallet := JSONWallet{privateKey, address}
      jsonBytes, _ := json.MarshalIndent(newWallet, "", "\t")
      jsonPayload := string(jsonBytes)
      file, err := os.OpenFile("wallet.json", os.O_WRONLY|os.O_CREATE, 0666)
      if err != nil {
          panic("Uh oh! Wallet file can't be created.")
      }
      defer file.Close()
  
      w := bufio.NewWriter(file)
      fmt.Fprint(w, jsonPayload)
  
      w.Flush()
      cwd, err := os.Getwd()
      println("Done! Wallet file location:\n" + cwd + fmt.Sprintf("%c", os.PathSeparator) + "wallet.json")
    }
    return nil
  }

  app.Run(os.Args)
}
