import rsa
import logging
from key_gen import RSAKeyGenerator

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def generate_fake_key():
    """Génère une fausse clé privée pour l'attaque."""
    try:
        logger.info("Génération d'une fausse clé RSA...")
        RSAKeyGenerator.generate_key_pair('client_fake')
        logger.info("✅ Fausse clé générée: client_fake_private.pem")
    except Exception as e:
        logger.error(f"❌ Erreur lors de la génération de la fausse clé: {e}")
        raise

if __name__ == "__main__":
    generate_fake_key()