import hashlib
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import socket
import random
#sender
#cilent


def H(data):
    # SHA-1 hash function
    return hashlib.sha1(data).digest()

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

def E(key, data):
    # AES encryption
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data)

    # Convert nonce and tag to bytes
    nonce_bytes = nonce
    tag_bytes = tag

    return nonce_bytes + ciphertext + tag_bytes


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
    # read file
    filename = 'file.txt'
    local_ip, local_port, local_pk, remote_ip, remote_port, remote_pk = read_file_and_store(filename)

    # if local_ip and local_port and local_pk and remote_ip and remote_port and remote_pk:
    #     print("Local IP cddress:", local_ip)
    #     print("Local port:", local_port)
    #     print("Local public key:", local_pk)
    #     print("Remote IP address:", remote_ip)
    #     print("Remote port:", remote_port)
    #     print("Remote public key:", remote_pk)

    # connect to socket
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.connect((local_ip, local_port))

    done = False

    while not done:
        # Send Message procedure

        # Generate sender's DH key pair
        p = 23  
        g = 9   
        x = 4  # Alice's private key
        # Replace with your random private key for sender
        sk_S, pk_S = generate_dh_key_pair(g, p, x)

        # ask for message:
        message = input("Message: ")

        if message == "quit":
            done = True
            break

        # Load or input message
        M = bytes(message, 'utf-8')

        # Step 1: Choose a random number r (nonce) from Z_p and compute g^r and TK=(pk_R)^r.
        r = 9  # random.randint() # Replace with your random nonce
        g_r = pow(g, r, p)

        TK = pow(remote_pk, r, p)  

        TK_bytes = TK.to_bytes(16, 'big')

        # Step 2: Use TK to encrypt M denoted by C=E(TK, M)
        C = E(TK_bytes, M)

        # Step 3: Compute LK=(pk_R)^(sk_S)
        LK = pow(remote_pk, sk_S, p)
        
        # Step 4: Compute MAC=H(LK || g^r || C || LK)
        data_to_hash = LK.to_bytes(
            16, 'big') + g_r.to_bytes(16, 'big') + C + LK.to_bytes(16, 'big')
        MAC = H(data_to_hash)

        # Step 5: Send (g^r, C, MAC) to the receiver.
        print("Encrypted Message Sent:")
        print("g^r:", g_r)
        print("C:", C)
        print("MAC:", MAC.hex())

        # Display M (replaced with (g^r, C, MAC) for security purpose)
        print("Original Message (replaced with (g^r, C, MAC)): ", (g_r, C, MAC))

        # convert g_r into bytes to send
        g_r_bytes = g_r.to_bytes(16, 'big')

        # add delimiter for concatenation
        encrypted_msg = g_r_bytes + b'\|' + C + b'\|' + MAC
        print('this is the encrypted sent message: ', encrypted_msg)
        # send (g^r, C, MAC)
        client.send(encrypted_msg)  

        #######################################################

        # receive reply from server
        server_response, _ = client.recvfrom(1024)
        
        # decrypt and reconstruct response
        arr = server_response.split(b'\|')
 
        # check if the message is correct
        print('this is the sent message: ', arr)

        # Load (g^r, C, MAC) received from the sender
        g_r = arr[0]
        C = arr[1]
        MAC = arr[2] 

        # Step 1: Compute TK=(g^r)^(sk_R)
        TK = pow(int.from_bytes(g_r, 'big'), sk_S, p)

        # Step 2: Compute LK=(pk_S)^(sk_R)
        LK = pow(remote_pk, sk_S, p)

        print("alice lk:" , LK)


        # Step 3: Compute MAC’=H(LK || g^r || C || LK)
        data_to_hash = LK.to_bytes(
            16, 'big') + g_r + C + LK.to_bytes(16, 'big')
        
        MAC_prime = H(data_to_hash)

        #check mac value
        # Step 4: Check if MAC=MAC'
        if MAC == MAC_prime:
            print("Message integrity verified.")

            # Step 5: Compute M'=D(TK, C)
            M_prime = D(TK.to_bytes(16, 'big'), C)
            print("Decrypted Message: ", M_prime.decode())

    client.close()



if __name__ == "__main__":
    main()




