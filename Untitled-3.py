import socket
import threading
import secrets
from typing import Optional, Tuple, Callable
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class DiffieHellman:
    """实现Diffie-Hellman密钥交换协议的核心功能"""
    
    def __init__(self, prime: int, generator: int):
        """
        初始化Diffie-Hellman协议实例
        
        参数:
            prime: 素数，协议的公共参数
            generator: 生成元，协议的公共参数
        """
        self.prime = prime
        self.generator = generator
        self.private_key = None
        self.public_key = None
        self.shared_secret = None
        
    def generate_private_key(self, bit_length: int = 256) -> int:
        """
        生成私钥（大随机数）
        
        参数:
            bit_length: 私钥的比特长度
            
        返回:
            私钥（整数）
        """
        self.private_key = secrets.randbits(bit_length)
        return self.private_key
        
    def compute_public_key(self) -> int:
        """
        计算公钥: generator^private_key mod prime
        
        返回:
            公钥（整数）
        """
        if self.private_key is None:
            raise ValueError("私钥未生成")
            
        self.public_key = pow(self.generator, self.private_key, self.prime)
        return self.public_key
        
    def compute_shared_secret(self, other_public_key: int) -> bytes:
        """
        计算共享密钥: other_public_key^private_key mod prime
        
        参数:
            other_public_key: 对方的公钥
            
        返回:
            共享密钥（字节串）
        """
        if self.private_key is None:
            raise ValueError("私钥未生成")
            
        shared_secret_int = pow(other_public_key, self.private_key, self.prime)
        # 转换为字节串
        byte_length = (shared_secret_int.bit_length() + 7) // 8
        self.shared_secret = shared_secret_int.to_bytes(byte_length, 'big')
        
        # 使用SHA-256进行密钥派生，生成固定长度的加密密钥
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(self.shared_secret)
        self.shared_secret = digest.finalize()
        
        return self.shared_secret
        
    def clear_secret_data(self):
        """清除敏感数据"""
        self.private_key = None
        self.shared_secret = None

class SecureChannel:
    """使用共享密钥建立安全通信通道"""
    
    NONCE_LENGTH = 12  # AES-GCM推荐的nonce长度为12字节
    TAG_LENGTH = 16    # AES-GCM默认的标签长度为16字节
    
    def __init__(self, shared_secret: bytes):
        """
        初始化安全通道
        
        参数:
            shared_secret: 共享密钥
        """
        self.shared_secret = shared_secret
        
    def encrypt(self, plaintext: str) -> bytes:
        """
        加密消息并格式化为固定长度字段的字节流
        
        参数:
            plaintext: 明文消息
            
        返回:
            格式化的加密数据: nonce(12字节) + 标签(16字节) + 密文
        """
        # 生成随机nonce
        nonce = secrets.token_bytes(self.NONCE_LENGTH)
        
        # 创建AES-GCM加密器
        cipher = Cipher(
            algorithms.AES(self.shared_secret),
            modes.GCM(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # 加密并生成认证标签
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        tag = encryptor.tag
        
        # 格式化为: nonce + tag + ciphertext
        return nonce + tag + ciphertext
    
    def decrypt(self, data: bytes) -> str:
        """
        从格式化的字节流中解密消息
        
        参数:
            data: 加密数据: nonce(12字节) + 标签(16字节) + 密文
            
        返回:
            明文字符串
        """
        # 分割数据
        nonce = data[:self.NONCE_LENGTH]
        tag = data[self.NONCE_LENGTH:self.NONCE_LENGTH + self.TAG_LENGTH]
        ciphertext = data[self.NONCE_LENGTH + self.TAG_LENGTH:]
        
        # 创建AES-GCM解密器
        cipher = Cipher(
            algorithms.AES(self.shared_secret),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # 解密并验证
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext.decode()

class DHClient:
    """Diffie-Hellman协议的客户端实现"""
    
    def __init__(self, dh: DiffieHellman, name: str = "Client"):
        """
        初始化客户端
        
        参数:
            dh: Diffie-Hellman协议实例
            name: 客户端名称，用于显示
        """
        self.dh = dh
        self.socket = None
        self.secure_channel = None
        self.name = name
        self.running = False
        
    def connect(self, host: str, port: int) -> bool:
        """
        连接到服务器
        
        参数:
            host: 服务器地址
            port: 服务器端口
            
        返回:
            连接成功返回True，失败返回False
        """
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((host, port))
            return True
        except Exception as e:
            print(f"连接错误: {e}")
            return False
            
    def execute_key_exchange(self) -> Optional[bytes]:
        """
        执行密钥交换过程
        
        返回:
            共享密钥（成功时），否则返回None
        """
        if not self.socket:
            return None
            
        try:
            # 生成私钥和公钥
            self.dh.generate_private_key()
            public_key = self.dh.compute_public_key()
            
            # 发送公钥给服务器
            self.socket.send(str(public_key).encode())
            
            # 接收服务器的公钥
            server_public_key = int(self.socket.recv(4096).decode())
            
            # 计算共享密钥
            shared_secret = self.dh.compute_shared_secret(server_public_key)
            
            # 创建安全通道
            self.secure_channel = SecureChannel(shared_secret)
            
            return shared_secret
        except Exception as e:
            print(f"密钥交换错误: {e}")
            return None
            
    def start_communication(self):
        """开始交互式通信"""
        if not self.secure_channel:
            print("安全通道未建立")
            return
            
        self.running = True
        
        # 启动接收线程
        receive_thread = threading.Thread(target=self._receive_messages)
        receive_thread.daemon = True
        receive_thread.start()
        
        # 处理用户输入
        print(f"{self.name} 可以开始发送消息了。输入 'exit' 退出。")
        try:
            while self.running:
                message = input(f"{self.name}: ")
                
                if message.lower() == 'exit':
                    self.running = False
                    break
                    
                if not self.send_message(message):
                    self.running = False
                    break
                    
        except KeyboardInterrupt:
            print("\n用户中断，正在关闭连接...")
            self.running = False
        finally:
            self.close()
            
    def _receive_messages(self):
        """接收消息的线程函数"""
        while self.running:
            try:
                message = self.receive_message()
                if message is None:
                    self.running = False
                    break
                    
                print(f"\nServer: {message}")
                print(f"{self.name}: ", end="", flush=True)  # 恢复输入提示符
                
            except Exception as e:
                if self.running:
                    print(f"接收消息时出错: {e}")
                self.running = False
                break
                
    def send_message(self, message: str) -> bool:
        """
        发送加密消息
        
        参数:
            message: 明文消息
            
        返回:
            发送成功返回True，失败返回False
        """
        if not self.secure_channel:
            print("安全通道未建立")
            return False
            
        try:
            # 加密消息
            encrypted_data = self.secure_channel.encrypt(message)
            
            # 发送长度前缀和加密数据
            length_prefix = len(encrypted_data).to_bytes(4, 'big')
            self.socket.sendall(length_prefix + encrypted_data)
            
            return True
        except Exception as e:
            print(f"发送消息错误: {e}")
            return False
            
    def receive_message(self) -> Optional[str]:
        """
        接收并解密消息
        
        返回:
            明文字符串（成功时），否则返回None
        """
        if not self.secure_channel:
            print("安全通道未建立")
            return None
            
        try:
            # 接收长度前缀
            length_bytes = self._receive_all(4)
            if not length_bytes:
                return None
                
            length = int.from_bytes(length_bytes, 'big')
            
            # 接收加密数据
            encrypted_data = self._receive_all(length)
            if not encrypted_data:
                return None
                
            # 解密消息
            plaintext = self.secure_channel.decrypt(encrypted_data)
            
            return plaintext
        except Exception as e:
            print(f"接收消息错误: {e}")
            return None
            
    def _receive_all(self, size: int) -> Optional[bytes]:
        """
        确保接收指定大小的所有字节
        
        参数:
            size: 需要接收的字节数
            
        返回:
            接收到的字节数据，或None（连接关闭）
        """
        data = b""
        while len(data) < size:
            chunk = self.socket.recv(size - len(data))
            if not chunk:
                return None
            data += chunk
        return data
            
    def close(self):
        """关闭连接"""
        self.running = False
        
        if self.socket:
            try:
                self.socket.close()
            except OSError:
                pass  # 忽略已关闭的套接字错误
            self.socket = None
            
        if self.dh:
            self.dh.clear_secret_data()
            
        self.secure_channel = None

class DHServer:
    """Diffie-Hellman协议的服务器端实现"""
    
    def __init__(self, dh: DiffieHellman, host: str = 'localhost', port: int = 8000):
        """
        初始化服务器
        
        参数:
            dh: Diffie-Hellman协议实例
            host: 服务器监听地址
            port: 服务器监听端口
        """
        self.dh = dh
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
        self.client_sockets = {}  # 跟踪所有客户端连接 {socket: (address, secure_channel)}
        self.lock = threading.Lock()  # 用于线程同步
        
    def start(self, max_connections: int = 5):
        """
        启动服务器，开始监听连接
        
        参数:
            max_connections: 最大连接数
        """
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(max_connections)
            self.running = True
            print(f"服务器在 {self.host}:{self.port} 监听")
            
            # 启动接受客户端连接的线程
            accept_thread = threading.Thread(target=self._accept_connections)
            accept_thread.daemon = True
            accept_thread.start()
            
            # 保持主线程运行，监听退出信号
            try:
                while self.running:
                    command = input("输入 'exit' 关闭服务器: ")
                    if command.lower() == 'exit':
                        self.running = False
                        break
            except KeyboardInterrupt:
                print("\n用户中断，正在关闭服务器...")
                self.running = False
                
        finally:
            self.stop()
            
    def _accept_connections(self):
        """接受客户端连接的线程函数"""
        while self.running:
            try:
                # 设置超时以检查running标志
                self.server_socket.settimeout(1.0)
                client_socket, client_address = self.server_socket.accept()
                
                with self.lock:
                    if not self.running:
                        # 如果服务器正在关闭，拒绝新连接
                        client_socket.close()
                        continue
                        
                    # 记录客户端连接
                    self.client_sockets[client_socket] = (client_address, None)
                
                print(f"接受来自 {client_address} 的连接")
                
                # 为每个客户端创建一个线程
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, client_address)
                )
                client_thread.daemon = True
                client_thread.start()
                
            except socket.timeout:
                # 超时继续循环，检查running标志
                continue
            except OSError as e:
                # 处理套接字错误
                if self.running:
                    print(f"接受连接时出错: {e}")
                else:
                    # 服务器正在关闭，忽略错误
                    pass
                    
    def _handle_client(self, client_socket: socket.socket, client_address: tuple):
        """
        处理客户端连接，执行密钥交换和消息通信
        
        参数:
            client_socket: 客户端套接字
            client_address: 客户端地址元组
        """
        try:
            # 为每个客户端创建独立的DH实例
            client_dh = DiffieHellman(
                prime=self.dh.prime,
                generator=self.dh.generator
            )
            
            # 生成私钥和公钥
            client_dh.generate_private_key()
            public_key = client_dh.compute_public_key()
            
            # 接收客户端的公钥
            client_public_key = int(client_socket.recv(4096).decode())
            
            # 发送公钥给客户端
            client_socket.send(str(public_key).encode())
            
            # 计算共享密钥
            shared_secret = client_dh.compute_shared_secret(client_public_key)
            
            # 创建安全通道
            secure_channel = SecureChannel(shared_secret)
            
            # 更新客户端连接信息
            with self.lock:
                if client_socket in self.client_sockets:
                    self.client_sockets[client_socket] = (client_address, secure_channel)
            
            print(f"与 {client_address} 成功交换密钥")
            
            # 发送欢迎消息
            welcome_msg = "欢迎连接到安全服务器！你可以开始发送消息了。"
            encrypted_data = secure_channel.encrypt(welcome_msg)
            length_prefix = len(encrypted_data).to_bytes(4, 'big')
            client_socket.sendall(length_prefix + encrypted_data)
            
            # 接收并处理客户端消息
            while True:
                # 接收长度前缀
                length_bytes = self._receive_all(client_socket, 4)
                if not length_bytes:
                    break
                    
                length = int.from_bytes(length_bytes, 'big')
                
                # 接收加密数据
                encrypted_data = self._receive_all(client_socket, length)
                if not encrypted_data:
                    break
                    
                # 解密消息
                plaintext = secure_channel.decrypt(encrypted_data)
                
                print(f"\n客户端 {client_address}: {plaintext}")
                print("Server: ", end="", flush=True)  # 恢复输入提示符
                
        except Exception as e:
            if self.running:
                print(f"处理客户端 {client_address} 时出错: {e}")
        finally:
            # 清除敏感数据
            if 'client_dh' in locals():
                client_dh.clear_secret_data()
                
            # 从客户端列表中移除并关闭连接
            with self.lock:
                if client_socket in self.client_sockets:
                    del self.client_sockets[client_socket]
                    
            try:
                client_socket.close()
            except OSError:
                pass  # 忽略已关闭的套接字错误
            
            print(f"客户端 {client_address} 连接已关闭")
            
    def send_to_client(self, client_socket: socket.socket, message: str) -> bool:
        """
        向指定客户端发送消息
        
        参数:
            client_socket: 客户端套接字
            message: 要发送的消息
            
        返回:
            发送成功返回True，失败返回False
        """
        with self.lock:
            if client_socket not in self.client_sockets:
                print("客户端连接不存在")
                return False
                
            client_address, secure_channel = self.client_sockets[client_socket]
            
            if not secure_channel:
                print("安全通道未建立")
                return False
                
        try:
            # 加密并发送消息
            encrypted_data = secure_channel.encrypt(message)
            length_prefix = len(encrypted_data).to_bytes(4, 'big')
            client_socket.sendall(length_prefix + encrypted_data)
            return True
        except Exception as e:
            print(f"发送消息到客户端 {client_address} 时出错: {e}")
            return False
            
    def broadcast(self, message: str, exclude_socket: Optional[socket.socket] = None):
        """
        向所有客户端广播消息
        
        参数:
            message: 要广播的消息
            exclude_socket: 要排除的客户端套接字（可选）
        """
        with self.lock:
            for client_socket, (client_address, secure_channel) in list(self.client_sockets.items()):
                if client_socket == exclude_socket or not secure_channel:
                    continue
                    
                try:
                    # 加密并发送消息
                    encrypted_data = secure_channel.encrypt(message)
                    length_prefix = len(encrypted_data).to_bytes(4, 'big')
                    client_socket.sendall(length_prefix + encrypted_data)
                except Exception as e:
                    print(f"广播消息到客户端 {client_address} 时出错: {e}")
            
    def _receive_all(self, sock: socket.socket, size: int) -> Optional[bytes]:
        """
        确保从套接字接收指定大小的所有字节
        
        参数:
            sock: 套接字
            size: 需要接收的字节数
            
            返回:
                接收到的字节数据，或None（连接关闭）
        """
        data = b""
        while len(data) < size:
            chunk = sock.recv(size - len(data))
            if not chunk:
                return None
            data += chunk
        return data
            
    def stop(self):
        """停止服务器运行"""
        self.running = False
        
        # 关闭所有客户端连接
        with self.lock:
            for client_socket in list(self.client_sockets.keys()):
                try:
                    client_socket.close()
                except OSError:
                    pass  # 忽略已关闭的套接字
            self.client_sockets.clear()
        
        # 关闭服务器套接字
        if self.server_socket:
            try:
                # 首先尝试解除阻塞（对于Windows系统）
                if hasattr(socket, 'SHUT_RDWR'):
                    self.server_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass  # 忽略已关闭的套接字
            
            try:
                self.server_socket.close()
            except OSError as e:
                print(f"关闭服务器套接字时出错: {e}")
            finally:
                self.server_socket = None

# 修改客户端示例代码
if __name__ == "__main__":
    # 使用预定义的安全素数和生成元 (2048位)
    # RFC 3526 - 组14
    PRIME = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
    GENERATOR = 2
    
    # 创建服务器
    server_dh = DiffieHellman(PRIME, GENERATOR)
    server = DHServer(server_dh, port=8000)
    
    # 启动服务器线程
    server_thread = threading.Thread(target=server.start)
    server_thread.daemon = True
    server_thread.start()
    
    # 给服务器启动时间
    import time
    time.sleep(1)
    
    # 创建客户端
    client_dh = DiffieHellman(PRIME, GENERATOR)
    client = DHClient(client_dh, name="客户端")
    
    # 客户端连接并执行密钥交换
    if client.connect('localhost', 8000):
        print("客户端已连接，正在执行密钥交换...")
        shared_key = client.execute_key_exchange()
        if shared_key:
            print(f"客户端计算的共享密钥: {shared_key.hex()[:16]}...")
            
            # 接收服务器的欢迎消息
            welcome_msg = client.receive_message()
            if welcome_msg:
                print(f"来自服务器的消息: {welcome_msg}")
                
            # 开始交互式通信
            client.start_communication()
        else:
            print("密钥交换失败")
            client.close()
    else:
        print("无法连接到服务器")
    
    # 给服务器时间处理消息
    time.sleep(2)
    
    # 停止服务器
    if server.running:
        print("正在停止服务器...")
        server.stop()
    
    # 等待服务器线程完全退出
    server_thread.join(timeout=2.0)
    if server_thread.is_alive():
        print("警告: 服务器线程未能及时退出")
    else:
        print("服务器已成功停止")
