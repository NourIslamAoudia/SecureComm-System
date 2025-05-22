import socket
import json
import logging
from crypto_utils import CryptoUtils

# Configuration
SERVER_HOST = "192.168.100.5"
SERVER_PORT = 9999
BUFFER_SIZE = 4096

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SecureClient:
    """Client sécurisé utilisant un chiffrement hybride RSA/AES."""
    
    def __init__(self, client_private_key_path: str = "client_private.pem",
                 server_public_key_path: str = "server_public.pem"):
        """
        Initialise le client sécurisé.
        
        Args:
            client_private_key_path: Chemin vers la clé privée du client
            server_public_key_path: Chemin vers la clé publique du serveur
        """
        self.client_private_key = CryptoUtils.load_rsa_key(client_private_key_path, 'private')
        self.server_public_key = CryptoUtils.load_rsa_key(server_public_key_path, 'public')
        logger.info("✅ Client sécurisé initialisé")

    def send_secure_message(self, message: str, host: str = SERVER_HOST, port: int = SERVER_PORT) -> None:
        """
        Envoie un message sécurisé au serveur.
        
        Args:
            message: Message à envoyer
            host: Adresse du serveur
            port: Port du serveur
        """
        try:
            logger.info(f"Envoi du message sécurisé: {message}")
            
            # Conversion du message en bytes
            message_bytes = message.encode('utf-8')
            
            # Signature du message
            signed_message = CryptoUtils.create_signed_message(message_bytes, self.client_private_key)
            
            # Chiffrement AES
            aes_data = CryptoUtils.encrypt_with_aes(signed_message)
            
            # Chiffrement de la clé AES avec RSA
            encrypted_aes_key = rsa.encrypt(aes_data['aes_key'], self.server_public_key)
            
            # Préparation des données pour l'envoi
            payload = {
                'aes_key': base64.b64encode(encrypted_aes_key).decode(),
                'nonce': base64.b64encode(aes_data['nonce']).decode(),
                'tag': base64.b64encode(aes_data['tag']).decode(),
                'ciphertext': base64.b64encode(aes_data['ciphertext']).decode()
            }
            
            # Envoi au serveur
            self._send_to_server(payload, host, port)
            logger.info("✅ Message envoyé avec succès")
            
        except Exception as e:
            logger.error(f"❌ Erreur lors de l'envoi: {e}")
            raise

    def _send_to_server(self, payload: Dict[str, str], host: str, port: int) -> None:
        """Envoie les données au serveur via socket."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                client_socket.connect((host, port))
                json_data = json.dumps(payload).encode('utf-8')
                client_socket.send(json_data)
                logger.info(f"Données envoyées à {host}:{port}")
        except Exception as e:
            logger.error(f"❌ Erreur de connexion au serveur: {e}")
            raise

def run_client():
    """Lance le client sécurisé."""
    print("=" * 60)
    print("ENVOI D'UN MESSAGE SÉCURISÉ")
    print("=" * 60)
    try:
        client = SecureClient()
        message = input("Entrez votre message sécurisé: ")
        client.send_secure_message(message)
    except Exception as e:
        print(f"❌ Erreur du client: {e}")

if __name__ == "__main__":
    run_client()