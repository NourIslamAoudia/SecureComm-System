import socket
import json
import base64
import logging
from typing import Dict

import rsa
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

class MITMAttacker:
    """Simulateur d'attaque Man-in-the-Middle."""
    
    def __init__(self, fake_private_key_path: str = "client_fake_private.pem",
                 server_public_key_path: str = "server_public.pem"):
        """
        Initialise l'attaquant MITM.
        
        Args:
            fake_private_key_path: Chemin vers la fausse clé privée
            server_public_key_path: Chemin vers la clé publique du serveur
        """
        try:
            self.fake_private_key = CryptoUtils.load_rsa_key(fake_private_key_path, 'private')
            self.server_public_key = CryptoUtils.load_rsa_key(server_public_key_path, 'public')
            logger.info("🎭 Attaquant MITM initialisé")
        except FileNotFoundError:
            logger.error("❌ Fausse clé privée non trouvée. Veuillez d'abord générer une fausse clé.")
            raise

    def launch_attack(self, malicious_message: str = "Message malveillant depuis l'attaquant!",
                     target_host: str = SERVER_HOST, target_port: int = SERVER_PORT) -> None:
        """
        Lance une attaque MITM en envoyant un message malveillant.
        
        Args:
            malicious_message: Message malveillant à envoyer
            target_host: Adresse du serveur cible
            target_port: Port du serveur cible
        """
        try:
            logger.info(f"🚨 Lancement de l'attaque MITM avec le message: {malicious_message}")
            
            # Conversion du message malveillant
            message_bytes = malicious_message.encode('utf-8')
            
            # Signature avec la fausse clé privée
            signed_message = CryptoUtils.create_signed_message(message_bytes, self.fake_private_key)
            
            # Chiffrement AES
            aes_data = CryptoUtils.encrypt_with_aes(signed_message)
            
            # Chiffrement de la clé AES avec la vraie clé publique du serveur
            encrypted_aes_key = rsa.encrypt(aes_data['aes_key'], self.server_public_key)
            
            # Préparation du payload malveillant
            payload = {
                'aes_key': base64.b64encode(encrypted_aes_key).decode(),
                'nonce': base64.b64encode(aes_data['nonce']).decode(),
                'tag': base64.b64encode(aes_data['tag']).decode(),
                'ciphertext': base64.b64encode(aes_data['ciphertext']).decode()
            }
            
            # Envoi de l'attaque
            self._send_malicious_payload(payload, target_host, target_port)
            logger.info("🎯 Attaque MITM lancée avec succès")
            
        except Exception as e:
            logger.error(f"❌ Erreur lors de l'attaque: {e}")
            raise

    def _send_malicious_payload(self, payload: Dict[str, str], host: str, port: int) -> None:
        """Envoie le payload malveillant au serveur."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as attacker_socket:
                attacker_socket.connect((host, port))
                json_data = json.dumps(payload).encode('utf-8')
                attacker_socket.send(json_data)
                logger.info(f"💥 Payload malveillant envoyé à {host}:{port}")
        except Exception as e:
            logger.error(f"❌ Erreur lors de l'envoi malveillant: {e}")
            raise

def run_attack():
    """Lance une simulation d'attaque MITM."""
    print("=" * 60)
    print("SIMULATION D'ATTAQUE MITM")
    print("=" * 60)
    try:
        attacker = MITMAttacker()
        malicious_msg = input("Entrez le message malveillant (ou appuyez sur Entrée pour le message par défaut): ")
        if not malicious_msg:
            malicious_msg = "🎭 Message malveillant depuis l'attaquant MITM!"
        attacker.launch_attack(malicious_msg)
    except Exception as e:
        print(f"❌ Erreur lors de l'attaque: {e}")

if __name__ == "__main__":
    run_attack()