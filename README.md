# -Diffie-Hellman-Protocol-Design
Detailed Design and Programming Implementation of the Diffie-Hellman Protocol
## 1 Diffie-Hellman 协议程序原理
Diffie-Hellman算法是一种安全的密钥交换协议，它允许两个用户在一个不安全的通道上协商出一个共享密钥。这个共享密钥可以用来对称加密他们之间的通信。换句话说，Diffie-Hellman算法能够确保即使第三方监听了通信，依然无法获得共享的密钥。  
步骤	描述   
1	选择一个大素数p和一个小于p的生成元g。  
2	用户A选择一个私有密钥a，并计算公开密钥A = g^a mod p。   
3	用户B选择一个私有密钥b，并计算公开密钥B = g^b mod p。   
4	用户A将公开密钥A发送给用户B，用户B将公开密钥B发送给用户A。   
5	用户A计算共享密钥S = B^a mod p，用户B计算共享密钥S = A^b mod p。   
6	用户A和用户B使用共享密钥S进行后续通信的加密。   
### 1.1代码实现   
我们这里定义了一个类class DiffieHellman用来实现Diffie-Hellman密钥交换协议的核心功能。   
其中def __init__(self, prime: int, generator: int)用于初始化Diffie-Hellman协议实例，即初始化素数，生成元，公钥，私钥等数据。   
def generate_private_key(self, bit_length: int = 256) -> int:用于生成私钥（大随机数），其返回值为私钥。   
def compute_public_key(self) -> int:用于计算公钥，其返回值为公钥（整数）。   
def compute_shared_secret(self, other_public_key: int) -> bytes:用于计算共享密钥，其返回值为共享密钥（字节串）。并且在生成共享密钥的时候使用SHA-256进行密钥派生，生成固定长度的加密密钥。   
def clear_secret_data(self):用于清除敏感数据   
## 2 安全通信通道的建立   
(1)初始化安全通道    
(2)加密消息并格式化为固定长度字段的字节流，之后返回格式化的加密数据: nonce(12字节) + 标签(16字节) + 密文   
(3)从格式化的字节流中解密消息   
在加密和解密的过程中，我们创建了一个AES-GCM解密器和一个AES-GCM加密器来完成。   
## 3 Diffie-Hellman协议的客户端实现   
首先初始化客户端   
def connect(self, host: str, port: int) -> bool:连接到服务器   
def execute_key_exchange(self) -> Optional[bytes]:执行密钥交换过程   
def start_communication(self):开始交互式通信   
def _receive_messages(self):接收消息的线程函数   
def send_message(self, message: str) -> bool:发送加密消息   
def receive_message(self) -> Optional[str]:接收并解密消息    
def _receive_all(self, size: int) -> Optional[bytes]:确保接收指定大小的所有字节    
def close(self):关闭连接    
## 4 Diffie-Hellman协议的服务器端实现    
def __init__(self, dh: DiffieHellman, host: str = 'localhost', port: int = 8000):初始化服务器     
def start(self, max_connections: int = 5):启动服务器，开始监听连接    
def _accept_connections(self):接受客户端连接的线程函数    
在这个函数里，我们设置了超时以检查running标志。 如果服务器正在关闭，会拒绝新连接。    
并且会记录客户端连接，为每个客户端创建一个线程。     
def _handle_client(self, client_socket: socket.socket, client_address: tuple):处理客户端连接，执行密钥交换和消息通信   
为每个客户端创建独立的DH实例，可以生成公钥私钥，计算共享密钥并创建安全通道，之后可以接收并处理客户端消息，最后清除敏感数据并关闭连接。    
def send_to_client(self, client_socket: socket.socket, message: str) -> bool:向指定客户端发送消息    
def broadcast(self, message: str, exclude_socket:Optional[socket.socket] = None):向所有客户端广播消息    
def _receive_all(self, sock: socket.socket, size: int) ->Optional[bytes]:确保从套接字接收指定大小的所有字节    
def stop(self):停止服务器运行    
## 5 通信实现实例   
这里由于生成大素数并计算共享密钥所耗费时间过长，演示时使用预先约定好的安全素数和生成元。    
