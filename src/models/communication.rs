use serde::{Serialize, Deserialize};
// use mongodb::bson::oid::ObjectId;

#[derive(Debug, Serialize, Deserialize)]
pub struct CommunicationPreferences {
    // #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    // pub id: Option<ObjectId>, // in case we wanna store as a collection in db
    // pub user_id: ObjectId, // Reference to User in case we wanna store as a collection in db
    pub receive_promotions_email: Option<bool>,
    pub receive_promotions_sms: Option<bool>,
    // Add more analytics providers as needed here ...
    // For example:
    // receive_news_email: Option<bool>,
    // receive_news_sms: Option<bool>,
    // receive_product_updates: Option<bool>,
    // receive_event_invitations: Option<bool>,
    // receive_surveys_feedback: Option<bool>,
    // receive_personalized_offers: Option<bool>,
    // receive_partner_offers: Option<bool>,
    // receive_reward_programs: Option<bool>,
    // receive_educational_content: Option<bool>,
    // receive_community_updates: Option<bool>,
    // receive_exclusive_content: Option<bool>,
    // receive_referral_programs: Option<bool>,
    // receive_birthday_anniversary_offers: Option<bool>,
    // receive_abandoned_cart_reminders: Option<bool>,
}