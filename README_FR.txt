WINCASH 3.0 — VERSION DE DÉPLOIEMENT RENDER
================================================

FONCTIONNALITÉS INCLUSES
- Comptes Client, Vendeur et Affilié.
- Connexion sécurisée par mot de passe haché (bcrypt) et sessions.
- Catalogue public, publication et gestion des produits.
- Prix, stock partagé, commission affilié et frais de livraison.
- Lien de recommandation affilié avec attribution à la commande.
- Commandes client, livraison ou retrait.
- Paiement en espèces uniquement au lancement.
- Le vendeur confirme la réception des espèces.
- Suivi des commandes : nouvelle, acceptée, préparation, prête, expédiée, livrée, annulée.
- Commission enregistrée à la commande, disponible uniquement après livraison et confirmation du paiement.
- Demandes de retrait affilié et traitement manuel par l'administrateur.
- Espace administrateur et suivi des commandes/retraits.
- Interface responsive et installable comme PWA.

IMPORTANT — AVANT LE LANCEMENT
Cette version est une base fonctionnelle de marketplace à tester en conditions réelles.
Elle ne contient PAS encore de paiement électronique, de vérification automatique de transfert,
de partage automatique des fonds, de système de remboursement automatisé, ni de gestionnaire
de litiges. Les retraits d'affiliés sont traités manuellement par l'administrateur.
Le vendeur doit confirmer le paiement en espèces dans son espace. Ne marquez une commande
comme livrée qu'après avoir reçu le paiement et remis le produit.

DÉPLOIEMENT LE PLUS SIMPLE SUR RENDER
1. Décompressez le ZIP en conservant la structure des dossiers.
2. Envoyez tous les fichiers du dossier WinCash_Final_Render dans un dépôt GitHub.
   À la racine du dépôt, vous devez voir : package.json, server.js, render.yaml et public/.
3. Sur Render, choisissez New > Blueprint et connectez ce dépôt.
4. Render lit render.yaml et crée le service web et la base PostgreSQL.
5. Dans les variables d'environnement du service, renseignez :
   ADMIN_EMAIL = votre adresse e-mail administrateur
   ADMIN_PASSWORD = un mot de passe long et unique (12 caractères ou plus).
   SESSION_SECRET est généré automatiquement par le Blueprint.
   DATABASE_URL est relié automatiquement à la base PostgreSQL.
6. Déployez. Vérifiez l'adresse /health : elle doit afficher {"ok":true,"service":"WinCash"}.
7. Ouvrez le site, créez les comptes vendeurs, affiliés et clients.

SI VOUS CRÉEZ LE SERVICE MANUELLEMENT
- Runtime : Node
- Build command : npm install
- Start command : npm start
- Ajouter une base PostgreSQL Render et relier sa variable DATABASE_URL au service.
- Définir NODE_ENV=production, SESSION_SECRET (secret aléatoire long),
  ADMIN_EMAIL et ADMIN_PASSWORD avant le premier démarrage.

SÉCURITÉ ET EXPLOITATION
- Ne publiez jamais ADMIN_PASSWORD ni SESSION_SECRET.
- Ne partagez pas le compte administrateur.
- Utilisez HTTPS (fourni par Render).
- Sauvegardez régulièrement la base PostgreSQL.
- Testez d'abord avec de petites commandes réelles et des comptes de test.
- Le forfait gratuit Render peut mettre le service en veille et ralentir le premier chargement.
- Une base PostgreSQL persistante est nécessaire : ne remplacez pas DATABASE_URL par un fichier local.

PAIEMENT
Au lancement, seul le paiement en espèces est proposé, à la livraison ou au retrait.
L'intégration future d'Afrimoney, d'un transfert bancaire ou d'une carte nécessitera un
contrat/API auprès du prestataire de paiement et des tests de validation. Cette version
n'encaisse pas l'argent à la place du vendeur.

LIMITES À CONNAÎTRE
- Un affilié ne peut pas modifier le prix ou la commission du vendeur.
- Le stock est décrémenté lors de la commande et restauré si la commande est annulée.
- Les commissions sont mises en disponibilité après confirmation du paiement et livraison.
- Les retraits affiliés sont manuels. L'administrateur doit vérifier le paiement externe avant
  de marquer une demande comme payée.
- La version doit faire l'objet d'un audit de sécurité, de tests de charge et d'une validation
  juridique/comptable locale avant une exploitation commerciale à grande échelle.
