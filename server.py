import socket
import json
import base64
import logging
from crypto_utils import CryptoUtils

# Configuration
SERVER_PORT = 9999
BUFFER_SIZE = 4096

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SecureServer:
    """Serveur sécurisé capable de recevoir et vérifier des messages chiffrés."""
    
    def __init__(self, server_private_key_path: str = "server_private.pem",
                 client_public_key_path: str = "client_public.pem"):
        """
        Initialise le serveur sécurisé.
        
        Args:
            server_private_key_path: Chemin vers la clé privée du serveur
            client_public_key_path: Chemin vers la clé publique du client
        """
        self.server_private_key = CryptoUtils.load_rsa_key(server_private_key_path, 'private')
        self.client_public_key = CryptoUtils.load_rsa_key(client_public_key_path, 'public')
        logger.info("✅ Serveur sécurisé initialisé")

    def start_server(self, host: str = "0.0.0.0", port: int = SERVER_PORT) -> None:
        """
        Démarre le serveur et écoute les connexions.
        
        Args:
            host: Adresse d'écoute
            port: Port d'écoute
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_socket.bind((host, port))
                server_socket.listen(1)
                
                logger.info(f"🚀 Serveur en écoute sur {host}:{port}")
                
                while True:
                    try:
                        conn, addr = server_socket.accept()
                        logger.info(f"📡 Connexion reçue de {addr}")
                        self._handle_client(conn)
                    except KeyboardInterrupt:
                        logger.info("🛑 Arrêt du serveur demandé")
                        break
                    except Exception as e:
                        logger.error(f"❌ Erreur lors de la gestion du client: {e}")
                        
        except Exception as e:
            logger.error(f"❌ Erreur du serveur: {e}")
            raise

    def _handle_client(self, connection: socket.socket) -> None:
        """Gère une connexion client."""
        try:
            with connection:
                data = connection.recv(BUFFER_SIZE)
                if data:
                    self._process_message(data)
        except Exception as e:
            logger.error(f"❌ Erreur lors du traitement du client: {e}")

    def _process_message(self, data: bytes) -> None:
        """Traite un message reçu."""
        try:
            # Décodage JSON
            payload = json.loads(data.decode('utf-8'))
            
            # Décodage des données base64
            encrypted_aes_key = base64.b64decode(payload['aes_key'])
            nonce = base64.b64decode(payload['nonce'])
            tag = base64.b64decode(payload['tag'])
            ciphertext = base64.b64decode(payload['ciphertext'])
            
            # Déchiffrement de la clé AES
            aes_key = rsa.decrypt(encrypted_aes_key, self.server_private_key)
            
            # Déchiffrement du message
            signed_message = CryptoUtils.decrypt_with_aes(aes_key, nonce, tag, ciphertext)
            
            # Vérification de la signature
            message, is_valid = CryptoUtils.verify_signed_message(signed_message, self.client_public_key)
            
            if is_valid:
                logger.info(f"✅ Message authentifié reçu: {message.decode('utf-8')}")
            else:
                logger.warning(f"⚠️  Message reçu mais signature invalide: {message.decode('utf-8')}")
                logger.warning("🚨 ATTENTION: Possible attaque MITM détectée!")
                
        except Exception as e:
            logger.error(f"❌ Erreur lors du traitement du message: {e}")

def run_server():
    """Lance le serveur sécurisé."""
    print("=" * 60)
    print("DÉMARRAGE DU SERVEUR SÉCURISÉ")
    print("=" * 60)
    try:
        server = SecureServer()
        server.start_server()
    except KeyboardInterrupt:
        print("\n🛑 Serveur arrêté par l'utilisateur")
    except Exception as e:
        print(f"❌ Erreur critique du serveur: {e}")

if __name__ == "__main__":
    run_server()