WINCASH 4.0 — VERSION BÊTA DE TRAVAIL
====================================

Cette archive est construite à partir du projet WinCash existant (Express + PostgreSQL + interface web).
Elle apporte une première base fonctionnelle pour les évolutions convenues. Elle ne doit pas être considérée comme une version de production entièrement validée.

FONCTIONS INCLUSES
------------------
- Comptes à adresse e-mail unique avec plusieurs rôles (client, vendeur, affilié, administrateur).
- Ajout de rôles à un compte existant après connexion avec le même mot de passe.
- Changement de l'espace actif entre les rôles autorisés.
- Suppression logique du compte avec confirmation du mot de passe et anonymisation du profil. Les références de commandes et de commissions restent conservées.
- Publication de produits avec photo choisie depuis le téléphone, prix, stock, frais et commission affilié obligatoire supérieure à zéro.
- Les anciens produits sans commission sont masqués jusqu'à ce que le vendeur définisse une commission positive.
- Liens affiliés signés, attribution vérifiée côté serveur, aperçu Open Graph avec image du produit.
- Coordonnées du vendeur sur les produits et coordonnées de l'affilié sur la page de commande issue de son lien.
- Commandes en espèces et suivi des commissions selon les fonctions de la version précédente.
- Messagerie privée textuelle entre membres.
- Création de groupes publics et privés (les invitations/gestion avancée des groupes restent à compléter).
- Création de pages publiques de boutique et publications textuelles avec URL média facultative.
- Portail d'administration distinct à /admin.

À COMPLÉTER AVANT UNE MISE EN PRODUCTION PUBLIQUE
-------------------------------------------------
- Messagerie temps réel, notifications et pièces jointes (photos/vidéos/documents).
- Invitations et rôles de modération dans les groupes privés.
- Abonnements aux pages, commentaires, réactions, signalements et outils de modération.
- Stockage média durable externe (les photos de produits actuelles sont stockées comme données dans PostgreSQL ; ce n'est pas le stockage recommandé à grande échelle).
- Tests fonctionnels complets avec une vraie base PostgreSQL, tests de sécurité, sauvegardes et règles de confidentialité des coordonnées publiques.
- Revue des obligations légales de conservation/suppression des données dans le pays d'exploitation.

DÉPLOIEMENT SUR RENDER
----------------------
1. Faire une sauvegarde du dépôt GitHub et de la base PostgreSQL avant remplacement.
2. Remplacer les fichiers du dépôt par ceux de cette archive en conservant la structure : server.js, package.json, render.yaml, public/.
3. Dans Render > Environment, vérifier que les variables suivantes existent :
   - DATABASE_URL (connexion PostgreSQL existante ; ne pas la remplacer par une autre base)
   - SESSION_SECRET (secret long et aléatoire)
   - ADMIN_EMAIL (adresse du compte administrateur)
   - ADMIN_PASSWORD (mot de passe administrateur fort)
   - NODE_ENV=production
4. Le compte ADMIN_EMAIL est créé ou promu administrateur au démarrage. Définir ADMIN_PASSWORD réinitialise son mot de passe à chaque redémarrage : ne le modifier que volontairement.
5. Attendre le déploiement puis vérifier /health et /admin.
6. Tester d'abord avec des comptes et produits fictifs. Ne pas traiter de vraies commandes avant les tests.

PORTAIL ADMIN
-------------
https://VOTRE-DOMAINE/admin

SÉCURITÉ ET PRÉCAUTIONS
----------------------
- Ne jamais publier ADMIN_PASSWORD ni SESSION_SECRET dans GitHub.
- Ne jamais remplacer DATABASE_URL par une URL inventée. Garder la base actuelle pour préserver les données.
- Effectuer une sauvegarde de la base avant la migration automatique.
- L'accès à /admin est contrôlé par le rôle admin ; connaître l'URL ne suffit pas.
