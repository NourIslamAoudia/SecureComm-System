def main():
    """Point d'entrée principal du programme."""
    print("=" * 60)
    print("SYSTÈME DE COMMUNICATION SÉCURISÉE")
    print("=" * 60)
    print("1. Générer les clés RSA")
    print("2. Lancer le serveur")
    print("3. Envoyer un message (client)")
    print("4. Simuler une attaque MITM")
    print("5. Quitter")
    print("=" * 60)
    
    while True:
        try:
            choice = input("\nVotre choix (1-5): ").strip()
            
            if choice == '1':
                from key_gen import run_key_generation
                run_key_generation()
            elif choice == '2':
                from server import run_server
                run_server()
            elif choice == '3':
                from client import run_client
                run_client()
            elif choice == '4':
                from attack import run_attack
                run_attack()
            elif choice == '5':
                print("👋 Au revoir!")
                break
            else:
                print("❌ Choix invalide. Veuillez choisir entre 1 et 5.")
                
        except KeyboardInterrupt:
            print("\n👋 Au revoir!")
            break
        except Exception as e:
            print(f"❌ Erreur: {e}")

if __name__ == "__main__":
    main()