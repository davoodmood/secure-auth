/*
    Compliance and Privacy Considerations:

    Ensure your authentication system complies with relevant regulations and standards 
    such as GDPR, HIPAA, or PCI DSS, depending on your application's domain and geography.

    Implementation Tip:
    - Implement features like data encryption at rest and in transit, audit logs, and user consent flows.
    - Regularly review and update your practices to remain compliant with changing regulations.

*/



// use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use mongodb::bson::oid::ObjectId;

#[derive(Debug, Serialize, Deserialize)]
pub struct DataPrivacySettings {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    id: Option<ObjectId>,
    user_id: ObjectId, // Reference to User
    analytics_consent: Option<AnalyticsConsent>,
    ad_tracking_consent: Option<AdTrackingConsent>,
    marketing_consent: Option<MarketingConsent>,
    personalization_consent: Option<PersonalizationConsent>,
    communication_consent: Option<CommunicationConsent>,
    lawful_basis: Option<LawfulBasis>, // Lawful basis for processing (GDPR)
    data_subject_rights: Option<DataSubjectRights>, // Data subject rights (GDPR)
    dpo_details: Option<DPODetails>, // Data Protection Officer details (GDPR)
    data_breach_notification: Option<DataBreachNotification>, // Data breach notification (GDPR)
    // CCPA-specific fields
    do_not_sell: Option<bool>, // Do not sell my personal information
    request_to_know: Option<bool>, // Right to know about personal information collected
    request_to_delete: Option<bool>, // Right to delete personal information
    request_to_opt_out: Option<bool>, // Right to opt-out of sale of personal information
    // Add more consent categories as needed here ...
}

#[derive(Debug, Serialize, Deserialize)]
struct AnalyticsConsent {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    id: Option<ObjectId>,
    data_privacy_settings_id: ObjectId, // Reference to DataPrivacySettings
    #[serde(skip_serializing_if = "Option::is_none")]
    google_analytics: Option<bool>,
    // Add more analytics providers as needed here ...
    // For example:
    // segment: Option<bool>,
    // mixpanel: Option<bool>,
    // adobe_analytics: bool,
    // kissmetrics: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct AdTrackingConsent {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    id: Option<ObjectId>,
    data_privacy_settings_id: ObjectId, // Reference to DataPrivacySettings
    facebook_ads: Option<bool>,
    google_ads: Option<bool>,
    twitter_ads: Option<bool>,
    linkedin_ads: Option<bool>,
    // Add more ad tracking providers as needed here ...
    // For example:
    // pinterest_ads: bool,
    // snapchat_ads: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct MarketingConsent {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    id: Option<ObjectId>,
    data_privacy_settings_id: ObjectId, // Reference to DataPrivacySettings
    email_marketing: Option<bool>,
    sms_marketing: Option<bool>,
    // Add more marketing channels as needed here ...
    // For example:
    // personalized_content: bool,
    // personalized_search_results: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersonalizationConsent {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    id: Option<ObjectId>,
    data_privacy_settings_id: ObjectId, // Reference to DataPrivacySettings
    personalized_recommendations: Option<bool>,
    personalized_ads: Option<bool>,
    // Add more personalization options as needed here ...
}

#[derive(Debug, Serialize, Deserialize)]
struct CommunicationConsent {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    id: Option<ObjectId>,
    data_privacy_settings_id: ObjectId, // Reference to DataPrivacySettings
    email_communication: Option<bool>,
    sms_communication: Option<bool>,
    push_notifications: Option<bool>,
    // Add more communication channels as needed here ...
    // For example:
    // in-app_notifications: bool,
    // direct_mail_communication: bool,

}

/*
    GDPR Related Structs 
*/

#[derive(Debug, Serialize, Deserialize)]
struct LawfulBasis {
    consent: bool,
    contract: bool,
    legal_obligation: bool,
    vital_interests: bool,
    public_task: bool,
    legitimate_interests: bool,
    // Add more lawful basis options as needed
}

#[derive(Debug, Serialize, Deserialize)]
struct DataSubjectRights {
    access: bool,
    rectify: bool,
    erase: bool,
    restrict_processing: bool,
    data_portability: bool,
    object: bool,
    // Add more data subject rights options as needed
}


// @dev: Some strange bug with choro deceerializtion. I'm not commiting due to example purpose only.
#[derive(Debug, Serialize, Deserialize)]
struct DataBreachNotification {
    notified: bool,
    notification_date: Option<i64>, // Unix time for notification_date timestamp
    // Add more data breach notification fields as needed
}

#[derive(Debug, Serialize, Deserialize)]
struct DPODetails {
    name: String,
    email: String,
    phone: String,
    // Add more DPO details as needed
}
