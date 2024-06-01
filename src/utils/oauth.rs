use oauth2::{ClientId, ClientSecret, RedirectUrl, AuthUrl, TokenUrl, AuthorizationCode, CsrfToken};
use oauth2::basic::BasicClient;
use std::env;

pub fn google_client() -> Result<BasicClient, Box<dyn std::error::Error>> {
    let client_id = std::env::var("GOOGLE_CLIENT_ID").expect("Missing GOOGLE_CLIENT_ID");
    let client_secret = std::env::var("GOOGLE_CLIENT_SECRET").expect("Missing GOOGLE_CLIENT_SECRET");
    let redirect_url = std::env::var("GOOGLE_REDIRECT_URL").expect("Missing GOOGLE_REDIRECT_URL");

    Ok(BasicClient::new(
        ClientId::new(client_id),
        Some(ClientSecret::new(client_secret)),
        AuthUrl::new("https://accounts.google.com/o/oauth2/auth".to_string())?,
        Some(TokenUrl::new("https://www.googleapis.com/oauth2/v3/token".to_string())?)
    )
    .set_redirect_uri(RedirectUrl::new(redirect_url)?))
}

pub fn facebook_client() -> Result<BasicClient, Box<dyn std::error::Error>> {
    let client_id = env::var("FACEBOOK_CLIENT_ID")?;
    let client_secret = env::var("FACEBOOK_CLIENT_SECRET")?;
    let redirect_url = env::var("FACEBOOK_REDIRECT_URL")?;

    Ok(BasicClient::new(
        ClientId::new(client_id),
        Some(ClientSecret::new(client_secret)),
        AuthUrl::new("https://www.facebook.com/v10.0/dialog/oauth".to_string())?,
        Some(TokenUrl::new("https://graph.facebook.com/v10.0/oauth/access_token".to_string())?)
    )
    .set_redirect_uri(RedirectUrl::new(redirect_url)?))
}


pub fn discord_client() -> Result<BasicClient, Box<dyn std::error::Error>> {
    let client_id = env::var("DISCORD_CLIENT_ID")?;
    let client_secret = env::var("DISCORD_CLIENT_SECRET")?;
    let redirect_url = env::var("DISCORD_REDIRECT_URL")?;

    Ok(BasicClient::new(
        ClientId::new(client_id),
        Some(ClientSecret::new(client_secret)),
        AuthUrl::new("https://discord.com/api/oauth2/authorize".to_string())?,
        Some(TokenUrl::new("https://discord.com/api/oauth2/token".to_string())?)
    )
    .set_redirect_uri(RedirectUrl::new(redirect_url)?))
}


pub fn _apple_client() -> Result<BasicClient, Box<dyn std::error::Error>> {
    let client_id = ClientId::new(env::var("APPLE_CLIENT_ID")?);
    let client_secret = ClientSecret::new(env::var("APPLE_CLIENT_SECRET")?);

    let auth_url = AuthUrl::new("https://appleid.apple.com/auth/authorize".to_string())?;
    let token_url = TokenUrl::new("https://appleid.apple.com/auth/token".to_string())?;

    Ok(BasicClient::new(client_id, Some(client_secret), auth_url, Some(token_url))
        .set_redirect_uri(RedirectUrl::new("http://localhost:8080/auth/apple/callback".to_string())?))
}

pub fn _twitter_client() -> Result<BasicClient, Box<dyn std::error::Error>> {
    let client_id = ClientId::new(env::var("TWITTER_CLIENT_ID")?);
    let client_secret = ClientSecret::new(env::var("TWITTER_CLIENT_SECRET")?);

    let auth_url = AuthUrl::new("https://api.twitter.com/oauth/authorize".to_string())?;
    let token_url = TokenUrl::new("https://api.twitter.com/oauth/access_token".to_string())?;

    Ok(BasicClient::new(client_id, Some(client_secret), auth_url, Some(token_url))
        .set_redirect_uri(RedirectUrl::new("http://localhost:8080/auth/twitter/callback".to_string())?))
}

pub fn _github_client() -> Result<BasicClient, Box<dyn std::error::Error>> {
    let client_id = ClientId::new(env::var("GITHUB_CLIENT_ID")?);
    let client_secret = ClientSecret::new(env::var("GITHUB_CLIENT_SECRET")?);

    let auth_url = AuthUrl::new("https://github.com/login/oauth/authorize".to_string())?;
    let token_url = TokenUrl::new("https://github.com/login/oauth/access_token".to_string())?;

    Ok(BasicClient::new(client_id, Some(client_secret), auth_url, Some(token_url))
        .set_redirect_uri(RedirectUrl::new("http://localhost:8080/auth/github/callback".to_string())?))
}

