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

![image](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/21593c99-af00-4127-a266-ceaba35bc1aa/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20221016%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20221016T084206Z&X-Amz-Expires=86400&X-Amz-Signature=f6cae5871ac5e6d50183cce0a0450eed2a509da564c84faaf7cc4dc0cc2aca6a&X-Amz-SignedHeaders=host&response-content-disposition=filename%20%3D%22Untitled.png%22&x-id=GetObject)

#### Step 4: Send Messages

Once the Server Public key is pasted onto the client's terminal, press enter to prompt the client to send messages to the server.

The following output should be observerd.

![image](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/725a7038-a710-4c78-b525-b35282d9a2c9/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20221016%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20221016T085021Z&X-Amz-Expires=86400&X-Amz-Signature=f399b90bf7fbfff0fe4a8723f1ddc6c72c0c43835bea4b28c50b3908993d01c7&X-Amz-SignedHeaders=host&response-content-disposition=filename%20%3D%22Untitled.png%22&x-id=GetObject)

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

#### Step 3: Run Program

``` bash
java Part2.EchoServer <storePassword> <keyPassword>
```
``` bash
java Part2.EchoClient <storePassword> <keyPassword>
```

Run the **server** program on one terminal and the **client** program on the other. Will also have to specify the *store* password (badpassword) and the *key* password.

**Note:** Ensure that the server program is run first so it's listening for incoming connections.

The following output should be observed.

![image](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/c6f1d684-8938-4b42-ad5b-f9d55216dc5c/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20221016%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20221016T085233Z&X-Amz-Expires=86400&X-Amz-Signature=9712437b6dde44e076fdfacc6134cb7fb06fdfbb47945f3022ac95afddb6fc22&X-Amz-SignedHeaders=host&response-content-disposition=filename%20%3D%22Untitled.png%22&x-id=GetObject)

### Section Three: Secure Channel

This sections uses asymmetric encryption for messages regarding key negotiation and once the symmetric keys are generated, symmetric encryption will be used for future messages. This continues until a max message limit is reached where key negotiation occurs again if there are more messages to be sent and received.

#### Step 1: Navigate to `src`

Open **two** terminals and nivigate to the the `src` folder of the project in **both** of the terminals.

``` bash
cd src
```

#### Step 2: Compilation

Compile the following files in one of the terminal sessions.

``` bash
javac Part3/EchoServer.java Part3/EchoClient.java Part3/Util.java
```

#### Step 3: Run Program

``` bash
java Part3x.EchoServer <storePassword> <keyPassword> [maxMessages]
```
``` bash
java Part3.EchoClient <storePassword> <keyPassword>
```

Run the server program on one terminal and the client program on the other. Will also have to specify the store password (badpassword) and the key password. The key password for both the client and server is password, for simplicity and testing purposes. 

When running the server program, the user can also specify the number of maximum messages that can be received before key negotiation has to be performed again. If not specified this value will be set to 5. 

**Note:** Ensure that the server is ran first and listening for connections.

The following output should be observed.

![image](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/8ee0d219-0322-4046-8824-8bc539e61def/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20221016%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20221016T085340Z&X-Amz-Expires=86400&X-Amz-Signature=9f81e3964720ca23aeee4972bce17932c04e3e174ca20435c4a101fd5aafc53f&X-Amz-SignedHeaders=host&response-content-disposition=filename%20%3D%22Untitled.png%22&x-id=GetObject)

![image](https://s3.us-west-2.amazonaws.com/secure.notion-static.com/85c0c9c1-4b50-439c-b820-dc42a3ddc783/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIAT73L2G45EIPT3X45%2F20221016%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20221016T085412Z&X-Amz-Expires=86400&X-Amz-Signature=363dad387f92effece50c8870a652932b4d7c1a7c27099863186f7c9685a4e8c&X-Amz-SignedHeaders=host&response-content-disposition=filename%20%3D%22Untitled.png%22&x-id=GetObject)
