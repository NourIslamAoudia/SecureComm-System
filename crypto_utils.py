import rsa
import logging
import base64
from pathlib import Path
from typing import Dict, Tuple
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

AES_KEY_SIZE = 16  # 128 bits

class CryptoUtils:
    """Utilitaires pour les opérations cryptographiques."""
    
    @staticmethod
    def load_rsa_key(key_path: str, key_type: str) -> rsa.key.AbstractKey:
        """
        Charge une clé RSA depuis un fichier.
        
        Args:
            key_path: Chemin vers le fichier de clé
            key_type: Type de clé ('public' ou 'private')
            
        Returns:
            Clé RSA chargée
        """
        try:
            if not Path(key_path).exists():
                raise FileNotFoundError(f"Fichier de clé non trouvé: {key_path}")
            
            with open(key_path, "rb") as f:
                key_data = f.read()
            
            if key_type == 'private':
                return rsa.PrivateKey.load_pkcs1(key_data)
            elif key_type == 'public':
                return rsa.PublicKey.load_pkcs1(key_data)
            else:
                raise ValueError("key_type doit être 'public' ou 'private'")
                
        except Exception as e:
            logger.error(f"❌ Erreur lors du chargement de la clé {key_path}: {e}")
            raise

    @staticmethod
    def create_signed_message(message: bytes, private_key: rsa.PrivateKey) -> bytes:
        """
        Crée un message signé numériquement.
        
        Args:
            message: Message à signer
            private_key: Clé privée pour la signature
            
        Returns:
            Message avec signature attachée
        """
        try:
            signature = rsa.sign(message, private_key, 'SHA-256')
            return message + b'||' + signature
        except Exception as e:
            logger.error(f"❌ Erreur lors de la signature: {e}")
            raise

    @staticmethod
    def verify_signed_message(signed_message: bytes, public_key: rsa.PublicKey) -> Tuple[bytes, bool]:
        """
        Vérifie un message signé numériquement.
        
        Args:
            signed_message: Message avec signature
            public_key: Clé publique pour la vérification
            
        Returns:
            Tuple (message_original, signature_valide)
        """
        try:
            message, signature = signed_message.split(b'||', 1)
            rsa.verify(message, signature, public_key)
            return message, True
        except rsa.VerificationError:
            logger.warning("❌ Signature invalide détectée!")
            return message, False
        except Exception as e:
            logger.error(f"❌ Erreur lors de la vérification: {e}")
            raise

    @staticmethod
    def encrypt_with_aes(data: bytes) -> Dict[str, str]:
        """
        Chiffre des données avec AES en mode EAX.
        
        Args:
            data: Données à chiffrer
            
        Returns:
            Dictionnaire contenant les éléments chiffrés encodés en base64
        """
        try:
            aes_key = get_random_bytes(AES_KEY_SIZE)
            cipher = AES.new(aes_key, AES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            
            return {
                'aes_key': aes_key,
                'nonce': cipher.nonce,
                'tag': tag,
                'ciphertext': ciphertext
            }
        except Exception as e:
            logger.error(f"❌ Erreur lors du chiffrement AES: {e}")
            raise

    @staticmethod
    def decrypt_with_aes(aes_key: bytes, nonce: bytes, tag: bytes, ciphertext: bytes) -> bytes:
        """
        Déchiffre des données AES en mode EAX.
        
        Args:
            aes_key: Clé AES
            nonce: Nonce utilisé pour le chiffrement
            tag: Tag d'authentification
            ciphertext: Données chiffrées
            
        Returns:
            Données déchiffrées
        """
        try:
            cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
            return cipher.decrypt_and_verify(ciphertext, tag)
        except Exception as e:
            logger.error(f"❌ Erreur lors du déchiffrement AES: {e}")
            raise