use actix_web::HttpResponse;
use chrono::{offset::LocalResult, DateTime, TimeZone, Timelike, Utc};
use futures::TryStreamExt;
use std::collections::HashMap;
use mongodb::{bson::{self, doc, Document}, Collection, Database};

use crate::models::user::{LoginAttempt, User};


#[derive(Debug)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

pub fn login_attempt_to_bson(login_attempt: &LoginAttempt) -> Document {
    doc! {
        "ip_address": &login_attempt.ip_address,
        "timestamp": login_attempt.timestamp,
        "geographic_location": &login_attempt.geographic_location,
        "device_info": &login_attempt.device_info,
    }
}

fn get_hour_from_timestamp(timestamp: i64) -> Option<u32> {
    match Utc.timestamp_opt(timestamp, 0) {
        LocalResult::None => None,
        LocalResult::Single(datetime) => Some(datetime.hour()),
        LocalResult::Ambiguous(_, _) => None, // Handle ambiguous case if needed
    }
}

fn get_datetime_from_timestamp(timestamp: i64) -> Option<DateTime<Utc>> {
    match Utc.timestamp_opt(timestamp, 0) {
        LocalResult::None => None,
        LocalResult::Single(datetime) => Some(datetime),
        LocalResult::Ambiguous(_, _) => None, // Handle ambiguous case if needed
    }
}



async fn get_last_known_ip(db: &Database, user_id: &str) -> Option<String> {
    let collection = db.collection::<LoginAttempt>("login_attempts");
    let filter = doc! { "user_id": user_id };
    let options = mongodb::options::FindOneOptions::builder()
        .sort(doc! {"timestamp": -1})
        .build();
    if let Ok(Some(attempt)) = collection.find_one(filter, Some(options)).await {
        Some(attempt.ip_address)
    } else {
        None
    }

}

async fn get_login_history(db: &Database, user_id: &str) -> Vec<LoginAttempt> {
    let collection = db.collection::<LoginAttempt>("login_attempts");
    let filter = doc! { "user_id": user_id };
    let options = mongodb::options::FindOptions::builder()
        .sort(doc! {"timestamp": -1}) // Sort by timestamp in descending order
        .limit(4) // Limiting to retrieve only the most recent 4 documents
        .build();

    if let Ok(mut cursor) = collection.find(filter, options).await {
        let mut login_attempts = vec![];

        while let Some(result) = match cursor.try_next().await {
            Ok(Some(doc)) => Some(doc),
            Ok(None) => None,
            Err(e) => {
                println!("Error retrieving next document from cursor: {}", e);
                None
            }
        } {
            if let Ok(document) = bson::to_document(&result) {
                match bson::from_document::<LoginAttempt>(document) {
                    Ok(login_attempt) => login_attempts.push(login_attempt),
                    Err(e) => {
                        println!("Error parsing login attempt document: {}", e);
                    }
                }
            } else {
                println!("Error converting MongoDB result to document");
                
            }
        }

        login_attempts
    } else {
        vec![]
    }
}


fn is_unusual_access_time(timestamp: i64) -> bool {
    // Implement logic to determine if the access time is unusual
    // For demonstration, let's consider accesses between 1 AM and 5 AM as unusual
    let is_unusual_hour = if let Some(hour) = get_hour_from_timestamp(timestamp) {
        hour < 5 && hour >= 1
    } else {
        false
    };

    is_unusual_hour
}

async fn is_rapid_successive_attempts(db: &Database, user_id: &str, current_attempt: &LoginAttempt) -> bool {
    let login_history = get_login_history(db, user_id).await;
    let current_attempt_time = match get_datetime_from_timestamp(current_attempt.timestamp) {
        Some(datetime) => datetime,
        None => return false, // If the timestamp is invalid, return false
    };
    
    let recent_attempts: Vec<&LoginAttempt> = login_history.iter()
        .filter(|attempt| {
            let attempt_time = match get_datetime_from_timestamp(attempt.timestamp) {
                Some(datetime) => datetime,
                None => return false, // If the timestamp is invalid, return false
            };
            attempt_time > (current_attempt_time - chrono::Duration::minutes(5))
        })
        .collect();
    
    recent_attempts.len() > 3 // Assume more than 3 attempts within 5 minutes is rapid
}

pub async fn assess_login_risk(db: &Database, user_id: &str, login_attempt: &LoginAttempt) -> RiskLevel {
    let last_known_ip = get_last_known_ip(db, user_id).await;

    if let Some(last_ip) = last_known_ip {
        if last_ip != login_attempt.ip_address {
            return RiskLevel::High;
        }
    }

    if is_rapid_successive_attempts(db, user_id, login_attempt).await {
        return RiskLevel::High;
    }

    if is_unusual_access_time(login_attempt.timestamp) {
        return RiskLevel::Medium;
    }

    // based on user agent
    // based on location or device

    RiskLevel::Low
}
