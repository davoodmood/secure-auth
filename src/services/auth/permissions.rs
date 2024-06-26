pub const READ: i32 = 0b0000000001;           // 1
pub const WRITE: i32 = 0b0000000010;          // 2
pub const DELETE: i32 = 0b0000000100;         // 4
pub const UPDATE: i32 = 0b0000001000;         // 8
pub const EXECUTE: i32 = 0b0000010000;        // 16
pub const ADMIN: i32 = 0b0000100000;          // 32
pub const MANAGE_USERS: i32 = 0b0001000000;   // 64
pub const INVITE_USERS: i32 = 0b0010000000;   // 128
pub const VIEW_FINANCES: i32 = 0b0100000000;  // 256
pub const MANAGE_FINANCES: i32 = 0b1000000000; // 512
