import rsa
import logging
from typing import Optional

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

RSA_KEY_SIZE = 2048

class RSAKeyGenerator:
    """Générateur de clés RSA pour le système de communication sécurisée."""
    
    @staticmethod
    def generate_key_pair(entity_name: str, key_size: int = RSA_KEY_SIZE) -> None:
        """
        Génère une paire de clés RSA pour une entité donnée.
        
        Args:
            entity_name: Nom de l'entité (client, server, etc.)
            key_size: Taille de la clé RSA en bits
        """
        try:
            logger.info(f"Génération des clés RSA pour {entity_name}...")
            public_key, private_key = rsa.newkeys(key_size)
            
            # Sauvegarde des clés
            public_file = f"{entity_name}_public.pem"
            private_file = f"{entity_name}_private.pem"
            
            with open(public_file, 'wb') as f:
                f.write(public_key.save_pkcs1('PEM'))
            
            with open(private_file, 'wb') as f:
                f.write(private_key.save_pkcs1('PEM'))
            
            logger.info(f"✅ Clés générées avec succès pour {entity_name}")
            logger.info(f"   - Clé publique: {public_file}")
            logger.info(f"   - Clé privée: {private_file}")
            
        except Exception as e:
            logger.error(f"❌ Erreur lors de la génération des clés: {e}")
            raise

    @staticmethod
    def generate_all_keys() -> None:
        """Génère les clés pour le client et le serveur."""
        RSAKeyGenerator.generate_key_pair('client')
        RSAKeyGenerator.generate_key_pair('server')

def run_key_generation():
    """Génère les clés RSA nécessaires au système."""
    print("=" * 60)
    print("GÉNÉRATION DES CLÉS RSA")
    print("=" * 60)
    RSAKeyGenerator.generate_all_keys()
    print("=" * 60)

if __name__ == "__main__":
    run_key_generation()