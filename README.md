# create-btc-wallet
**Create  a new Bitcoin wallet right from the command line!**  
*Warning: This project is experimental. Please use at your own risk. The author is not liable for any loss of funds attributed to the use of this software.*  
*Note: While development of a pure Go implementation of the secp256k1 elliptic curve digital signature algorithm is underway, CBW will only provide you with a valid private key to import into a wallet client, not a public key.*  

*Dependencies:*  
Go  

**Get Started**  
1. Clone this repository
```
git clone https://github.com/aunyks/create-btc-wallet.git
```
2. Enter the newly created directory
```
cd create-btc-wallet
```
3. Build the source code and create and executable
```
go build cbw.go
```
4. (Optional) Copy the newly created executable to your Path  

5. Create a new Bitcoin wallet!
```
# On macOS / Linux
./cbw
```
```
rem On Windows
start cbw.exe
```
