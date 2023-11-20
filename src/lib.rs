use std::collections::{HashMap};

use jwt_simple::prelude::{

    RSAKeyPairLike,
    RS256KeyPair,
    Claims, 
};

pub use jwt_simple::prelude::{Duration as TokenDuration};

use actions_toolkit::client::{Client};

use anyhow::{Result};

pub use secrecy::{
    
    ExposeSecret,
    Secret,
};

use serde::{
        
    Deserialize,
    Serialize,
};

#[derive(Hash, PartialEq, Eq, Clone, Debug)]
#[derive(Serialize, Deserialize)]
pub enum Privileges {
    #[serde(rename = "read")] Read,
    #[serde(rename = "write")] Write,
    #[serde(rename = "admin")] Admin,
}

#[derive(Clone, Debug)]
#[derive(Hash, PartialEq, Eq)]
#[derive(Serialize, Deserialize)]
pub enum Scope {
    #[serde(rename = "actions")]
    Actions,
    #[serde(rename = "administration")]
    Administration,
    #[serde(rename = "checks")]
    Checks,
    #[serde(rename = "contents")]
    Contents,
    #[serde(rename = "deployments")]
    Deployments,
    #[serde(rename = "environments")]
    Environments,
    #[serde(rename = "issues")]
    Issues,
    #[serde(rename = "metadata")]
    Metadata,
    #[serde(rename = "packages")]
    Packages,
    #[serde(rename = "pages")]
    Pages,
    #[serde(rename = "pull-requests")]
    PullRequests,
    #[serde(rename = "repository-hooks")]
    RepositoryHooks,
    #[serde(rename = "repository-projects")]
    RepositoryProjects,
    #[serde(rename = "secret-scanning-alerts")]
    SecretScanningAlerts,
    #[serde(rename = "secrets")]
    Secrets,
    #[serde(rename = "security-events")]
    SecurityEvents,
    #[serde(rename = "single-file")]
    SingleFile,
    #[serde(rename = "statuses")]
    Statuses,
    #[serde(rename = "vulnerability-alerts")]
    VulnerabilityAlerts,
    #[serde(rename = "workflows")]
    Workflows, 
    #[serde(rename = "members")]
    Members,
    #[serde(rename = "organization-administration")]
    OrganizationAdministration,
    #[serde(rename = "organization-custom-roles")]
    OrganizationCustomRoles,
    #[serde(rename = "organization-announcement-banners")]
    OrganizationAnnouncementBanners,
    #[serde(rename = "organization-hooks")]
    OrganizationHooks,
    #[serde(rename = "organization-personal-access-tokens")]
    OrganizationPersonalAccessTokens,
    #[serde(rename = "organization-personal-access-token-requests")]
    OrganizationPersonalAccessTokenRequests,
    #[serde(rename = "organization-plan")]
    OrganizationPlan,
    #[serde(rename = "organization-projects")]
    OrganizationProjects,
    #[serde(rename = "organization-packages")]
    OrganizationPackages,
    #[serde(rename = "organization-secrets")]
    OrganizationSecrets,
    #[serde(rename = "organization-self-hosted-runners")]
    OrganizationSelfHostedRunners,
    #[serde(rename = "organization-user-blocking")]
    OrganizationUserBlocking,
    #[serde(rename = "team-discussions")]
    TeamDiscussions,
}

#[derive(Clone, Debug)]
enum TokenKind {
    Organization(String),
    Repository(String),
    User(String),
}

#[derive(Clone, Debug)]
pub struct TokenOptions {
    pub(crate) kind: TokenKind,
    pub(crate) duration: TokenDuration,
    pub(crate) permissions: Option<Permissions>,
}

impl TokenOptions {
    pub fn organization(organization: impl AsRef<str>) -> TokenOptions {
        let organization = organization.as_ref();

        TokenOptions { 
            kind: TokenKind::Organization({
                organization.to_owned()
            }),
            permissions: None,
            duration: TokenDuration::from_mins(10),
        }
    }

    pub fn repository(repository: impl AsRef<str>) -> TokenOptions {
        let repository = repository.as_ref();

        TokenOptions { 
            kind: TokenKind::Repository({
                repository.to_owned()
            }),
            permissions: None,
            duration: TokenDuration::from_mins(10),
        }
    }

    pub fn user(user: impl AsRef<str>) -> TokenOptions {
        let user = user.as_ref();

        TokenOptions { 
            kind: TokenKind::User({
                user.to_owned()
            }),
            permissions: None,
            duration: TokenDuration::from_mins(10),
        }
    }

    pub fn with_duration(mut self, duration: TokenDuration) -> TokenOptions {
        self.duration = duration;
        
        self
    }

    pub fn with_permissions(mut self, permissions: Permissions) -> TokenOptions {
        self.permissions = Some(permissions);
        self
    }
}

#[derive(Default, Clone, Debug)]
#[derive(Serialize, Deserialize)]
pub struct Permissions {
    #[serde(skip_serializing_if = "Option::is_none")]
    repositories: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scopes: Option<HashMap<Scope, Privileges>>,
}

impl Permissions {
    pub fn new() -> Permissions {
        Permissions { 
            repositories: None,
            scopes: None,
        }
    }

    pub fn new_with_repositories(repositories: impl AsRef<[String]>) -> Permissions {
        Self::new().with_repositories(repositories)
    }

    pub fn new_with_scopes(scopes: impl AsRef<[(Scope, Privileges)]>) -> Permissions {
        Self::new().with_scopes(scopes)
    }

    pub fn with_repositories<R>(mut self, identifiers: impl AsRef<[R]>) -> Permissions
    where R: AsRef<str> {

        let mut repositories = self.repositories.unwrap_or_default();
        repositories.extend(identifiers.as_ref().iter()
            .map(|repository| repository.as_ref()
                .to_owned()));

        self.repositories = Some(repositories);
        self
    }

    pub fn with_scopes(mut self, scopes: impl AsRef<[(Scope, Privileges)]>) -> Permissions {
        let mut permissions = self.scopes.unwrap_or_default();

        for (scope, privilege) in scopes.as_ref() {
            permissions.insert(scope.clone(), {
                privilege.clone()
            });
        }

        self.scopes = Some(permissions);
        self
    }
}

pub fn fetch_token(app_id: Secret<String>, app_pk: Secret<String>, options: TokenOptions) -> Result<Secret<String>> {
    let TokenOptions { kind, duration, permissions } = options;

    let token = Some(RS256KeyPair::from_pem(app_pk.expose_secret())?
        .sign(Claims::create(duration).with_issuer({
            app_id.expose_secret()
        }))?);

    let client = { Client::new_with_token(token)? };
    
    #[derive(Clone, Debug)]
    #[derive(Deserialize)]
    struct Installation {
        id: usize,
    }

    let Installation { id } = match kind {
        TokenKind::Organization(organization) => {
            client.get(format!("orgs/{organization}/installation"))?
                .send()?.json()?
        },
        TokenKind::Repository(repository) => {
            client.get(format!("repos/{repository}/installation"))?
                .send()?.json()?
        },
        TokenKind::User(user) => {
            client.get(format!("users/{user}/installation"))?
                .send()?.json()?
        },
    };

    #[derive(Clone, Debug)]
    #[derive(Deserialize)]
    struct Token {
        token: Secret<String>,
    }

    let Token { token } = {

        if let Some(ref permissions) = permissions {
            client.post(format!("app/installations/{id}/access_tokens"))?
                .json(permissions)
                .send()?.json()?
        }
        
        else {

            client.post(format!("app/installations/{id}/access_tokens"))?
                .send()?.json()?
        }
    };

    Ok(token)
}