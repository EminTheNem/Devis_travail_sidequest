# Suivi des demandes & devis — version serveur

Application web pour un petit artisan : demandes clients, statuts, montants, dates de relance, tableau de bord et export CSV. Les données sont conservées dans SQLite côté serveur (pas dans le navigateur).

## Ce qui est inclus
- Connexion administrateur, session serveur et protection CSRF.
- Limitation des tentatives de connexion et des appels API.
- Validation des données côté serveur, requêtes SQL préparées.
- En-têtes de sécurité, cookie de session HttpOnly/SameSite.
- Base SQLite persistante, journal d'actions, export CSV.
- Envoi facultatif d'un e-mail d'accusé de réception via SMTP.
- Docker Compose et contrôle de santé.

## Démarrage local
Prérequis : Docker et Docker Compose.

1. Copiez `.env.example` vers `.env`.
2. Créez un mot de passe administrateur fort et calculez son empreinte :
   ```bash
   node -e "console.log(require('crypto').scryptSync('VOTRE_MOT_DE_PASSE_LONG','change-this-salt',64).toString('hex'))"
   ```
3. Collez le résultat dans `ADMIN_PASSWORD_SCRYPT_HEX`. Remplacez `SESSION_SECRET` par une chaîne aléatoire longue (32 caractères minimum). Changez le nom d'utilisateur.
4. Lancez :
   ```bash
   docker compose up -d --build
   ```
5. Ouvrez `http://localhost:3000`.

## Mise en production : indispensables avant d'y mettre des clients
- Déployer derrière un reverse proxy HTTPS (Caddy, Nginx ou plateforme équivalente). Ne pas exposer directement le port applicatif à Internet. Le port Compose est lié à localhost.
- Si le proxy termine TLS, régler `TRUST_PROXY=1` uniquement si le proxy est maîtrisé et correctement configuré.
- Configurer SMTP avec un fournisseur fiable et tester la délivrabilité. L'envoi d'accusé est déclenché manuellement dans cette version via API; l'interface ne le déclenche pas encore.
- Mettre en place des sauvegardes chiffrées et testées de `./data`, avec restauration vérifiée.
- Restreindre l'accès au serveur, appliquer les mises à jour, surveiller les journaux et vérifier les alertes.
- Définir les mentions d'information RGPD, la base légale, les durées de conservation, les droits des personnes, le contrat de sous-traitance/hébergement et la procédure de suppression. Ne stocker aucune donnée sensible.
- Ajouter un compte distinct par utilisateur avant tout usage multi-employés. Cette version est mono-administrateur.
- Vérifier les exigences légales, contractuelles et de sécurité applicables à votre activité et à votre hébergeur.

## Limites connues
Ce paquet est une base déployable pour un pilote contrôlé, pas une certification de sécurité ni une garantie de conformité RGPD. Il ne comprend pas encore : formulaire public avec anti-spam, rôles multi-utilisateurs, sauvegardes automatisées, réinitialisation de mot de passe, envoi automatique planifié des relances, intégration Google Sheets/n8n, ni interface pour l'envoi manuel des accusés. L'endpoint SMTP existe, mais il faut l'intégrer au parcours métier et tester avec vos propres identifiants. Ne promettez pas d'automatisation d'e-mail ou de relance tant que cela n'a pas été testé en environnement réel.
