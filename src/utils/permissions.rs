use std::collections::HashMap;
use crate::services::auth::permissions;

pub fn get_route_permissions() -> HashMap<String, i32> {
    let mut route_permissions = HashMap::new();
    route_permissions.insert("/admin".to_string(), permissions::ADMIN);
    route_permissions.insert("/manage_users".to_string(), permissions::MANAGE_USERS);
    route_permissions.insert("/invite_users".to_string(), permissions::INVITE_USERS);
    route_permissions.insert("/view_finances".to_string(), permissions::VIEW_FINANCES);
    route_permissions.insert("/manage_finances".to_string(), permissions::MANAGE_FINANCES);
    route_permissions
}
