import hashlib
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import socket
#receiver
#server


def read_file_and_store(filename):
    try:
        with open(filename, 'r') as file:
            lines = file.readlines()

            if len(lines) >= 3:
                local_ip = lines[0].strip()
                local_port = int(lines[1].strip())
                local_pk = int(lines[2].strip())
                remote_ip = lines[3].strip()
                remote_port = int(lines[4].strip())
                remote_pk = int(lines[5].strip())

                return local_ip, local_port, local_pk, remote_ip, remote_port, remote_pk
            else:
                print("Not enough lines in the file.")
                return None, None, None, None, None, None
    except Exception as e:
        print("An error occurred:", str(e))
        return None, None, None, None, None, None

def H(data):
    # SHA-1 hash function
    return hashlib.sha1(data).digest()


def E(key, data):
    # AES encryption
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return nonce + ciphertext + tag


def D(key, data):
    # AES decryption
    nonce = data[:16]
    ciphertext = data[16:-16]
    tag = data[-16:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext


def generate_dh_key_pair(g, p, x):
    # Generate DH key pair
    sk = x
    pk = pow(g, x, p)
    return sk, pk


def main():
    filename = 'file.txt'
    local_ip, local_port, local_pk, remote_ip, remote_port, remote_pk = read_file_and_store(filename)

    # if local_ip and local_port and local_pk and remote_ip and remote_port and remote_pk:
    #     print("Local IP cddress:", local_ip) #alice: 127.0.0.1
    #     print("Local port:", local_port) #alice: 9999
    #     print("Local public key:", local_pk) #alice: 6
    #     print("Remote IP address:", remote_ip) #bob:  #127.0.0.1
    #     print("Remote port:", remote_port) #bob: 9999
    #     print("Remote public key:", remote_pk) #bob: 16
        

    # using internet to connect
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((remote_ip, remote_port))  # port 9999

    #server.listen()

    #client, addr = server.accept()

    done = False

    while not done:
        
        # Receive message procedure
        msg , client_address = server.recvfrom(1024)  # .decode('utf-8')
        arr = msg.split(b'\|')

        # check if the message is correct
        print('this is the sent message: ', arr)

        # Load or input sender's public key
        remote_pk = local_pk  # alice's public key

        # Generate receiver's DH key pair
        p = 23 
        g = 9   
        x = 3  # Bobs private key
        #Replace with your random private key for receiver
        sk_R, pk_R = generate_dh_key_pair(g, p, x)

        # split message(btyes) into 3 parts
        # Load (g^r, C, MAC) received from the sender
        g_r = arr[0]
        C = arr[1]
        MAC = arr[2] 

        # Step 1: Compute TK=(g^r)^(sk_R)
        TK = pow(int.from_bytes(g_r, 'big'), sk_R, p)

        # Step 2: Compute LK=(pk_S)^(sk_R)
        LK = pow(remote_pk, sk_R, p)

        # Step 3: Compute MAC’=H(LK || g^r || C || LK)
        data_to_hash = LK.to_bytes(
            16, 'big') + g_r + C + LK.to_bytes(16, 'big')
          # g_r.to_bytes(16, 'big')
          
        MAC_prime = H(data_to_hash)
        
        # Step 4: Check if MAC=MAC'
        if MAC == MAC_prime:
            print("Message integrity verified.")

            # Step 5: Compute M'=D(TK, C)
            M_prime = D(TK.to_bytes(16, 'big'), C)
            print("Decrypted Message: ", M_prime.decode())

            # send response to client
            response = input("Enter a message to send back to the client: ")

            ################################################################

            # encrypt message procedure: 
            # Load or input message
            response_bytes = bytes(response, 'utf-8')
            
            # Step 1: Choose a random number r (nonce) from Z_p and compute g^r and TK=(pk_R)^r.
            r = 9  # random.randint() # Replace with your random nonce
            g_r = pow(g, r, p)

            TK = pow(remote_pk, r, p)
            TK_bytes = TK.to_bytes(16, 'big')

            # Step 2: Use TK to encrypt M denoted by C=E(TK, M)
            C = E(TK_bytes, response_bytes)

            # Step 3: Compute LK=(pk_R)^(sk_R)
            LK = pow(remote_pk, sk_R, p)

             # Step 4: Compute MAC=H(LK || g^r || C || LK)
            data_to_hash = LK.to_bytes(
                16, 'big') + g_r.to_bytes(16, 'big') + C + LK.to_bytes(16, 'big')

            MAC = H(data_to_hash)

            # Step 5: Send (g^r, C, MAC) to the receiver.
            # Display M (replaced with (g^r, C, MAC) for security purpose)
            print("Original Message (replaced with (g^r, C, MAC)): ", (g_r, C, MAC))

            # convert g_r into bytes to send
            g_r_bytes = g_r.to_bytes(16, 'big')
            # add delimiter for concatenation
            encrypted_msg = g_r_bytes + b'\|' + C + b'\|' + MAC

            # send response
            server.sendto(encrypted_msg, client_address)

        else:
            print("ERROR: Message integrity verification failed.")

    server.close()


if __name__ == "__main__":
    main()
