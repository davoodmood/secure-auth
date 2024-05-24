use mongodb::{Client, options::ClientOptions, Database};
use std::env;

pub async fn init_database() -> Database {
    dotenv::dotenv().ok(); // Load .env file
    let db_uri = env::var("MONGODB_URI").expect("MONGODB_URI must be set");
    let db_name = env::var("MONGODB_NAME").expect("MONGODB_NAME must be set");

    let mut client_options = ClientOptions::parse(&db_uri).await.expect("Failed to connect to MongoDB");
    client_options.app_name = Some("AuthenticationSystem".to_string());
    let client = Client::with_options(client_options).expect("Failed to initialize MongoDB client");

    client.database(&db_name)
}
