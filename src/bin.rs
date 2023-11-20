use anyhow::{Result};

use jwt_simple::prelude::{Duration};

use secrecy::{
    
    ExposeSecret,
    Secret,
};

use actions_toolkit::{core as atc};
use token::TokenOptions;

fn main() -> Result<()> {
    let Some(repository) = atc::get_input("github-repository") else {
        atc::log::error("Missing input 'github-repository'!");
        anyhow::bail!("Missing input 'github-repository'!")
    };

    let Some(app_id) = atc::get_input("app-id")
        .map(|secret| Secret::from(secret)) else {
            atc::log::error("Missing input 'app-id'!");
            anyhow::bail!("Missing input 'app-id'!")
        };

    let Some(app_pk) = atc::get_input("app-pk")
        .map(|secret| Secret::from(secret)) else {
            atc::log::error("Missing input 'app-pk'!");
            anyhow::bail!("Missing input 'app-pk'!")
        };

    let permissions = {
        
        atc::get_input("permissions")
            .map(|string| serde_yaml::from_str(string.as_str()))
            .transpose()?
    };

    let duration = {
        
        atc::get_input("duration").map(|string| {
            u64::from_str_radix(string.as_str(), 10)
        }).transpose()?
    };

    let result = match permissions {
        Some(permissions) => token::fetch_token(app_id, app_pk, TokenOptions::repository(repository)
            .with_duration(Duration::from_mins(duration.unwrap_or(5))).with_permissions(permissions)),
        None => token::fetch_token(app_id, app_pk, TokenOptions::repository(repository)
            .with_duration(Duration::from_mins(duration.unwrap_or(5)))),
    };
    
    let Ok(token) = result else {
        atc::log::error("Failed to fetch token!");
        anyhow::bail!("Failed to fetch token!")
    };

    atc::add_secret_mask({
        token.expose_secret()
    })?;

    Ok(atc::set_output("token", {
        token.expose_secret()
    })?)
}