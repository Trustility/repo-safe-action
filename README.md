# Trustility Repo-Safe Proof

Cette action émet une preuve Trustility pour une étape GitHub Actions. Elle envoie uniquement
un hash canonique de coordonnées CI abstraites. Elle ne lit ni ne transmet le code source, les
différentiels, les patchs, les journaux ou les champs d’identité humaine/client. La clé API et,
si utilisé, le JWK privé de signature sont lus localement comme entrées explicites et ne quittent
jamais le runner.

## État de publication

Le dépôt ne contient actuellement **aucun tag stable ni aucune release publiée**. L’exemple utilise
donc `Trustility/repo-safe-action@main`. L’adresse par défaut de l’API est
`https://trustility.ai`; il n’existe pas de sous-domaine `api` à configurer.

## Préparer un premier dépôt

Avant de copier le workflow :

1. Créez un compte Trustility et une clé API. La clé est affichée uniquement au moment de son
   émission ; conservez-la dans le secret GitHub `TRUSTILITY_API_KEY`.
2. Créez ou revendiquez un agent et copiez son UUIDv4 canonique en minuscules dans la variable
   GitHub `TRUSTILITY_AGENT_ID`.
3. Créez une policy active et copiez sa référence dans le workflow. `pol:baseline@1` est la
   policy système active ; une policy de compte est préférable lorsque vous contrôlez son cycle
   de vie.

## Exemple complet copiable

Ce fichier peut être copié dans `.github/workflows/trustility-proof.yml`. Les deux valeurs
`TRUSTILITY_API_KEY` et `TRUSTILITY_AGENT_ID` doivent être créées comme indiqué ci-dessus avant
le premier lancement.

```yaml
name: Trustility proof

on:
  push:

permissions:
  contents: read

jobs:
  proof:
    runs-on: ubuntu-latest
    steps:
      - name: Emit Trustility proof
        id: trustility
        uses: Trustility/repo-safe-action@main
        with:
          policy-ref: pol:baseline@1
          api-key: ${{ secrets.TRUSTILITY_API_KEY }}
          agent-id: ${{ vars.TRUSTILITY_AGENT_ID }}

      - name: Show proof outputs
        run: |
          test "${{ steps.trustility.outputs.status }}" = "emitted"
          test -n "${{ steps.trustility.outputs.proof-id }}"
          test -n "${{ steps.trustility.outputs.event-hash }}"
```

Le workflow fournit automatiquement `api-url` avec sa valeur par défaut. Pour une autre instance
explicitement configurée, passez `api-url`; la valeur attendue est une origine HTTPS sans slash
final.

## Entrées

| Entrée | Obligatoire | Défaut | Description |
| --- | --- | --- | --- |
| `api-url` | non | `https://trustility.ai` | Origine du proof rail. |
| `api-key` | oui | — | Clé API Trustility, envoyée uniquement en en-tête Bearer. |
| `agent-id` | oui | — | UUIDv4 canonique en minuscules d’un agent revendiqué par cette clé. |
| `policy-ref` | oui | — | Référence d’une policy active, par exemple `pol:baseline@1`. |
| `proof-type` | non | `Integrity` | `Integrity`, `Reliability` ou `Oversight`. |
| `agent-key` | non | vide | JWK privé Ed25519 facultatif pour signer le hash ; ce n’est pas une authentification API. |
| `fail-on-error` | non | `true` | Échoue l’étape si l’API n’accepte pas la preuve. |

`event-data`, `nonce` et `ts_hint` ne sont pas des entrées. L’action les construit elle-même afin
que les métadonnées envoyées restent fermées et que le nonce soit unique.

## Sorties

| Sortie | Description |
| --- | --- |
| `proof-id` | Identifiant de la preuve acceptée. |
| `vc` | VC-JWT retourné par le proof rail. |
| `event-hash` | Hash canonique prouvé (`sha256:...`). |
| `status` | `emitted` ou `failed`. |

## Ce qui est transmis

Le corps de `POST /v1/proofs` contient :

- `ci`: la valeur fixe `github-actions` ;
- `repo`: `GITHUB_REPOSITORY` ;
- `ref`: `GITHUB_REF` ;
- `sha`: `GITHUB_SHA` ;
- `workflow`: `GITHUB_WORKFLOW` ;
- `event`: `GITHUB_EVENT_NAME` ;
- `run_id`: `GITHUB_RUN_ID` ;
- `run_attempt`: `GITHUB_RUN_ATTEMPT` ;
- `policyRef`, `type`, l’UUID `agentId`, un nonce aléatoire et un horodatage ISO générés par
  l’action.

La clé API n’est jamais placée dans le JSON : elle est uniquement dans
`Authorization: Bearer <clé>`, sans être journalisée.

## Ce qui ne quitte jamais le runner

Le code source, le contenu des fichiers, les différentiels, les patchs, les logs, les commandes,
les variables d’environnement non listées ci-dessus, les secrets autres que les entrées explicites
`api-key` et `agent-key`, les tokens, mots de passe,
identifiants de clé, en-têtes, cookies, prompts, messages, corps de requêtes et données client ne
sont ni lus ni transmis. L’action ne prend plus de champ `event-data` arbitraire.

`repo`, `workflow`, `ref` et `sha` sont des coordonnées GitHub et peuvent indirectement révéler
le nom d’une organisation ou d’un client si le dépôt en contient un. Ils sont nécessaires à la
preuve et ne sont pas traités comme un mécanisme d’anonymisation.

## Erreurs courantes

L’action échoue avant le réseau si `api-key`, `agent-id` ou `policy-ref` manque, et explique la
correction. Elle mappe les réponses actuelles du proof rail : clé absente/invalide,
`AGENT_REQUIRED`, `AGENT_NOT_OWNED`, `UNKNOWN_POLICY`, `POLICY_INACTIVE`, `CLOCK_SKEW`,
`EXPIRED_TIMESTAMP` et `NONCE_REPLAY`. Un nonce rejoué déclenche une nouvelle tentative avec un
nonce frais. Les erreurs inconnues sont réduites à leur statut et à une consigne générique ; le
corps brut et la clé ne sont jamais affichés.

## Dépendances

Node.js 20 ou plus récent est fourni par les runners GitHub hébergés. L’action n’a aucune
dépendance npm à installer.

## Licence

Apache License 2.0. Voir [LICENSE](./LICENSE).