# Secure Channel Echo Server and Client

The objective of this project was to implement a secure communications channel. Asymmetric encryption, signatures and key management in Java will be utilised to implement a secure protocol.

The project is divided into three sections, with each section built on top of the previous solution. The first section introduces asymmetric encryption, the second introduces key management and finally the third combines the previous two to implement a secure protocol.

The project consists of an Echo Server and a Client program. The server will just echo back the messages recieved back to the client. Howerver, the messages that are passed over the communication channel will be encrypted. 

## How to run

### Section One: Asymmetric Encryption

#### Step 1: Navigate to `src`

Open **two** terminals and nivigate to the the `src` folder of the project in **both** of the terminals.

``` bash
cd src
```

#### Step 2: Compilation

Compile the following files in one of the terminal sessions.

``` bash
javac Part1/EchoServer.java Part1/EchoClient.java Part1/Util.java
```

#### Step 3: Run Client and Server Program

Run the **server** program on one terminal and **client** program on the other

``` bash
java Part1.EchoServer
```
``` bash
java Part1.EchoClient
```

The following output should be observed

![image](https://user-images.githubusercontent.com/69548022/138545509-975b04f9-ea3c-4b8f-9157-c8bbf82f2dfd.png)

#### Step 4: Exchange Public Keys

First paste the **Client** Public key onto the server's terminal and press enter so the server starts listenning for connections. Then paste the **Server** public key onto the client's terminal.

![image](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/e012f684-6b0a-41ea-a8fd-f08520989910/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAT73L2G45O3KS52Y5%2F20211023%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20211023T063618Z&X-Amz-Expires=86400&X-Amz-Signature=85a4ba14b2b71a6c00d6ab8746e2596e92f07607be843e4d0a52388173e8e83f&X-Amz-SignedHeaders=host&response-content-disposition=filename%20%3D%22Untitled.png%22)

#### Step 4: Send Messages

Once the Server Public key is pasted onto the client's terminal, press enter to prompt the client to send messages to the server.

The following output should be observerd.

![image](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/725a7038-a710-4c78-b525-b35282d9a2c9/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAT73L2G45O3KS52Y5%2F20211023%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20211023T064146Z&X-Amz-Expires=86400&X-Amz-Signature=580f4360259e59314d63d80d333a7de4cbb33158bb5fa1019ee213538dbeb026&X-Amz-SignedHeaders=host&response-content-disposition=filename%20%3D%22Untitled.png%22)

### Section Two: Key management

The keys were generated using the keytool command which comes with the JCE. The client and server keys were created with same key password for testing purposes. The following commands shown below were used to generate the keys. 
``` bash
keytool -genkey -alias client -keyalg RSA -keystore cybr372.jks -storepass badpassword -keypass password -storetype JKS
```
``` bash
keytool -genkey -alias server -keyalg RSA -keystore cybr372.jks -storepass badpassword -keypass password -storetype JKS
```

#### Step 1: Navigate to `src`

Open **two** terminals and nivigate to the the `src` folder of the project in **both** of the terminals.

``` bash
cd src
```

#### Step 2: Compilation

Compile the following files in one of the terminal sessions.

``` bash
javac Part2/EchoServer.java Part2/EchoClient.java Part2/Util.java
```

### Step 3: Run Program

``` bash
java Part2.EchoServer <storePassword> <keyPassword>
```
``` bash
java Part2.EchoClient <storePassword> <keyPassword>
```

Run the **server** program on one terminal and the **client** program on the other. Will also have to specify the *store* password (badpassword) and the *key* password.

**Note:** Ensure that the server program is run first so it's listening for incoming connections.

The following output should be observed.

![image](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/c6f1d684-8938-4b42-ad5b-f9d55216dc5c/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAT73L2G45O3KS52Y5%2F20211024%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20211024T065650Z&X-Amz-Expires=86400&X-Amz-Signature=dafbe783b11878c744b30d67d159ee40ceb2f421962c6ce7c9d21e8424dfae1e&X-Amz-SignedHeaders=host&response-content-disposition=filename%20%3D%22Untitled.png%22)

